//! Server directory — the list of signaling and relay servers a client
//! knows about, and where that list comes from.
//!
//! Entries come from three sources, merged in this order (later sources
//! shadow earlier ones by name):
//!
//! 1. **Built-in** — compiled-in defaults so a dev build works on
//!    localhost out of the box.
//! 2. **Manifest** — a JSON document the project operator hosts at any
//!    HTTPS URL. Adding a new public server to the fleet is a one-line
//!    edit to that file; every client picks it up on its next refresh.
//!    The last successfully fetched manifest is cached on disk so
//!    clients keep their server list across offline restarts.
//! 3. **Custom** — entries the local user added by hand (their own
//!    self-hosted servers).
//!
//! Everything is persisted in `servers.toml` in the data directory.

use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::error::{HermesError, Result};

/// Manifest URL baked in at build time (`HERMES_DEFAULT_MANIFEST_URL`), used
/// when the user hasn't configured one. Empty/unset in ordinary builds.
const DEFAULT_MANIFEST_URL: Option<&str> = match option_env!("HERMES_DEFAULT_MANIFEST_URL") {
    Some(u) if !u.is_empty() => Some(u),
    _ => None,
};

/// Default manifest refresh timeout.
const MANIFEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// File name inside the data directory.
const DIRECTORY_FILE: &str = "servers.toml";

/// Which fleet a server belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerKind {
    /// WebSocket rendezvous server (`ws://` / `wss://` URL).
    Signaling,
    /// UDP relay ("central") server (`host:port`).
    Relay,
}

/// Where an entry came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerSource {
    /// Compiled-in default.
    BuiltIn,
    /// Fetched from the operator's manifest.
    Manifest,
    /// Added locally by the user.
    Custom,
}

/// One server the client can use.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerEntry {
    /// Display name — also the identity used for de-duplication.
    pub name: String,
    /// `ws(s)://…` URL for signaling servers, `host:port` for relays.
    pub address: String,
    /// Provenance of this entry.
    pub source: ServerSource,
}

/// The operator-hosted manifest document.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Manifest {
    /// Schema version, currently 1.
    #[serde(default)]
    pub version: u32,
    /// Signaling servers.
    #[serde(default)]
    pub signaling: Vec<ManifestServer>,
    /// Relay servers.
    #[serde(default)]
    pub relays: Vec<ManifestServer>,
}

/// One server as listed in the manifest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManifestServer {
    /// Display name.
    pub name: String,
    /// `ws(s)://…` URL or `host:port`.
    pub address: String,
}

/// On-disk persisted state (`servers.toml`).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PersistedDirectory {
    /// URL of the operator's manifest, if configured.
    manifest_url: Option<String>,
    /// Name of the signaling server the user selected.
    active_signaling: Option<String>,
    /// User-added signaling servers.
    #[serde(default)]
    custom_signaling: Vec<ManifestServer>,
    /// User-added relay servers.
    #[serde(default)]
    custom_relays: Vec<ManifestServer>,
    /// Cache of the last fetched manifest (survives offline restarts).
    #[serde(default)]
    cached_manifest: Manifest,
}

/// The merged, queryable server directory.
#[derive(Clone, Debug, Default)]
pub struct ServerDirectory {
    persisted: PersistedDirectory,
}

impl ServerDirectory {
    /// Built-in defaults — localhost endpoints so development works with
    /// zero configuration.
    fn builtin_signaling() -> Vec<ServerEntry> {
        vec![ServerEntry {
            name: "Local".into(),
            address: "ws://127.0.0.1:8787/v1".into(),
            source: ServerSource::BuiltIn,
        }]
    }

    fn builtin_relays() -> Vec<ServerEntry> {
        vec![ServerEntry {
            name: "Local relay".into(),
            address: "127.0.0.1:8788".into(),
            source: ServerSource::BuiltIn,
        }]
    }

    /// Load the directory from `data_dir`, falling back to defaults if
    /// the file is missing or unreadable.
    #[must_use]
    pub fn load(data_dir: &Path) -> Self {
        let path = data_dir.join(DIRECTORY_FILE);
        let persisted = match std::fs::read_to_string(&path) {
            Ok(text) => match toml::from_str::<PersistedDirectory>(&text) {
                Ok(p) => p,
                Err(e) => {
                    warn!(?e, "servers.toml is corrupt — starting from defaults");
                    PersistedDirectory::default()
                }
            },
            Err(_) => PersistedDirectory::default(),
        };
        Self { persisted }
    }

    /// Persist the directory to `data_dir`.
    ///
    /// # Errors
    /// Fails on serialization or I/O error.
    pub fn save(&self, data_dir: &Path) -> Result<()> {
        std::fs::create_dir_all(data_dir)?;
        let text = toml::to_string_pretty(&self.persisted)
            .map_err(|e| HermesError::Serialization(e.to_string()))?;
        std::fs::write(data_dir.join(DIRECTORY_FILE), text)?;
        Ok(())
    }

    /// The merged signaling server list.
    #[must_use]
    pub fn signaling_servers(&self) -> Vec<ServerEntry> {
        Self::merge(
            Self::builtin_signaling(),
            &self.persisted.cached_manifest.signaling,
            &self.persisted.custom_signaling,
        )
    }

    /// The merged relay server list.
    #[must_use]
    pub fn relay_servers(&self) -> Vec<ServerEntry> {
        Self::merge(
            Self::builtin_relays(),
            &self.persisted.cached_manifest.relays,
            &self.persisted.custom_relays,
        )
    }

    fn merge(
        builtin: Vec<ServerEntry>,
        manifest: &[ManifestServer],
        custom: &[ManifestServer],
    ) -> Vec<ServerEntry> {
        let mut out = builtin;
        for (list, source) in [
            (manifest, ServerSource::Manifest),
            (custom, ServerSource::Custom),
        ] {
            for s in list {
                // Same name shadows an earlier source.
                out.retain(|e| e.name != s.name);
                out.push(ServerEntry {
                    name: s.name.clone(),
                    address: s.address.clone(),
                    source,
                });
            }
        }
        out
    }

    /// The configured manifest URL.
    #[must_use]
    pub fn manifest_url(&self) -> Option<&str> {
        self.persisted
            .manifest_url
            .as_deref()
            .or(DEFAULT_MANIFEST_URL)
    }

    /// Set or clear the manifest URL.
    pub fn set_manifest_url(&mut self, url: Option<String>) {
        self.persisted.manifest_url = url;
    }

    /// Name of the user-selected signaling server, if any.
    #[must_use]
    pub fn active_signaling(&self) -> Option<&str> {
        self.persisted.active_signaling.as_deref()
    }

    /// Select the signaling server to use, by name.
    ///
    /// # Errors
    /// Fails if no server with that name exists.
    pub fn set_active_signaling(&mut self, name: &str) -> Result<()> {
        if !self.signaling_servers().iter().any(|s| s.name == name) {
            return Err(HermesError::Room(format!(
                "no signaling server named {name}"
            )));
        }
        self.persisted.active_signaling = Some(name.to_string());
        Ok(())
    }

    /// Resolve the signaling URL to connect to: the active selection if
    /// it still exists, otherwise the first server in the list.
    #[must_use]
    pub fn resolve_signaling_url(&self) -> Option<String> {
        let servers = self.signaling_servers();
        if let Some(active) = self.active_signaling() {
            if let Some(s) = servers.iter().find(|s| s.name == active) {
                return Some(s.address.clone());
            }
        }
        servers.first().map(|s| s.address.clone())
    }

    /// Add a user-defined server.
    ///
    /// # Errors
    /// Fails on an empty name/address.
    pub fn add_custom(&mut self, kind: ServerKind, name: String, address: String) -> Result<()> {
        if name.trim().is_empty() || address.trim().is_empty() {
            return Err(HermesError::Room("server name and address required".into()));
        }
        let list = match kind {
            ServerKind::Signaling => &mut self.persisted.custom_signaling,
            ServerKind::Relay => &mut self.persisted.custom_relays,
        };
        list.retain(|s| s.name != name);
        list.push(ManifestServer { name, address });
        Ok(())
    }

    /// Remove a user-defined server by name. Built-in and manifest
    /// entries cannot be removed locally (hide them by shadowing).
    ///
    /// # Errors
    /// Fails if no custom server with that name exists.
    pub fn remove_custom(&mut self, kind: ServerKind, name: &str) -> Result<()> {
        let list = match kind {
            ServerKind::Signaling => &mut self.persisted.custom_signaling,
            ServerKind::Relay => &mut self.persisted.custom_relays,
        };
        let before = list.len();
        list.retain(|s| s.name != name);
        if list.len() == before {
            return Err(HermesError::Room(format!("no custom server named {name}")));
        }
        Ok(())
    }

    /// Fetch the manifest from the configured URL and replace the cached
    /// copy. No-op if no manifest URL is configured.
    ///
    /// # Errors
    /// Fails on network or parse errors; the previous cache is kept.
    pub async fn refresh_manifest(&mut self) -> Result<bool> {
        let Some(url) = self.manifest_url().map(str::to_owned) else {
            return Ok(false);
        };
        info!(%url, "refreshing server manifest");
        let client = reqwest::Client::builder()
            .timeout(MANIFEST_TIMEOUT)
            .build()
            .map_err(|e| HermesError::Signaling(format!("http client: {e}")))?;
        let manifest: Manifest = client
            .get(&url)
            .send()
            .await
            .map_err(|e| HermesError::Signaling(format!("fetch manifest: {e}")))?
            .error_for_status()
            .map_err(|e| HermesError::Signaling(format!("manifest status: {e}")))?
            .json()
            .await
            .map_err(|e| HermesError::Signaling(format!("parse manifest: {e}")))?;
        info!(
            signaling = manifest.signaling.len(),
            relays = manifest.relays.len(),
            "manifest refreshed"
        );
        self.persisted.cached_manifest = manifest;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_defaults_present() {
        let dir = ServerDirectory::default();
        assert!(!dir.signaling_servers().is_empty());
        assert!(!dir.relay_servers().is_empty());
        assert!(dir.resolve_signaling_url().is_some());
    }

    #[test]
    fn custom_shadows_builtin_by_name() {
        let mut dir = ServerDirectory::default();
        dir.add_custom(
            ServerKind::Signaling,
            "Local".into(),
            "ws://10.0.0.1:1/v1".into(),
        )
        .unwrap();
        let servers = dir.signaling_servers();
        let local: Vec<_> = servers.iter().filter(|s| s.name == "Local").collect();
        assert_eq!(local.len(), 1);
        assert_eq!(local[0].address, "ws://10.0.0.1:1/v1");
        assert_eq!(local[0].source, ServerSource::Custom);
    }

    #[test]
    fn active_selection_resolves() {
        let mut dir = ServerDirectory::default();
        dir.add_custom(
            ServerKind::Signaling,
            "VPS".into(),
            "wss://vps.example/v1".into(),
        )
        .unwrap();
        dir.set_active_signaling("VPS").unwrap();
        assert_eq!(
            dir.resolve_signaling_url().as_deref(),
            Some("wss://vps.example/v1")
        );
        assert!(dir.set_active_signaling("Nope").is_err());
    }

    #[test]
    fn save_and_load_roundtrip() {
        let tmp = std::env::temp_dir().join(format!("hermes-dir-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let mut dir = ServerDirectory::default();
        dir.add_custom(ServerKind::Relay, "My relay".into(), "1.2.3.4:8788".into())
            .unwrap();
        dir.set_manifest_url(Some("https://example.com/m.json".into()));
        dir.save(&tmp).unwrap();

        let loaded = ServerDirectory::load(&tmp);
        assert!(loaded.relay_servers().iter().any(|s| s.name == "My relay"));
        assert_eq!(loaded.manifest_url(), Some("https://example.com/m.json"));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn remove_custom_only() {
        let mut dir = ServerDirectory::default();
        dir.add_custom(ServerKind::Relay, "Mine".into(), "1.1.1.1:1".into())
            .unwrap();
        dir.remove_custom(ServerKind::Relay, "Mine").unwrap();
        assert!(dir.remove_custom(ServerKind::Relay, "Local relay").is_err());
    }
}
