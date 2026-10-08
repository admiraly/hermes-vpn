//! UPnP IGD port mapping — ask the home router to forward a public UDP
//! port to our socket, which makes us directly reachable even behind a
//! NAT that would otherwise defeat hole punching.
//!
//! Best effort by design: many routers ship with UPnP disabled, so every
//! failure is just "no UPnP candidate" to the caller.
//!
//! A mapping is a lease on someone else's router, so it is managed for
//! its whole life: [`UpnpMapping::renew`] refreshes it before the lease
//! runs out (the engine does this on a timer), and [`UpnpMapping::remove`]
//! deletes it when the node shuts down instead of leaving a stale port
//! forward behind.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use igd_next::aio::tokio::{search_gateway, Tokio};
use igd_next::aio::Gateway;
use igd_next::{PortMappingProtocol, SearchOptions};
use tracing::{debug, info};

use crate::error::{HermesError, Result};

/// How long to wait for a gateway to answer SSDP discovery.
const SEARCH_TIMEOUT: Duration = Duration::from_secs(3);
/// Requested mapping lifetime. Routers that reject finite leases are
/// retried with 0 (= indefinite, the only value some IGDv1 boxes accept).
const LEASE_SECS: u32 = 3600;

/// A live port mapping on the local gateway.
#[derive(Clone, Debug)]
pub struct UpnpMapping {
    gateway: Gateway<Tokio>,
    /// The public address peers can reach us at.
    pub external: SocketAddrV4,
    local: SocketAddr,
    /// Granted lease in seconds; 0 means indefinite.
    pub lease_secs: u32,
    description: String,
}

impl UpnpMapping {
    /// How often to renew: half the lease, so one lost renewal is harmless.
    /// `None` for an indefinite lease.
    #[must_use]
    pub fn renew_interval(&self) -> Option<Duration> {
        (self.lease_secs > 0).then(|| Duration::from_secs(u64::from(self.lease_secs) / 2))
    }

    /// Refresh the lease (re-adding a mapping with the same parameters is
    /// how IGD renews).
    ///
    /// # Errors
    /// Fails if the gateway refuses or is unreachable.
    pub async fn renew(&self) -> Result<()> {
        self.gateway
            .add_port(
                PortMappingProtocol::UDP,
                self.external.port(),
                self.local,
                self.lease_secs,
                &self.description,
            )
            .await
            .map_err(|e| HermesError::Nat(format!("UPnP renew: {e}")))?;
        debug!(external = %self.external, "UPnP mapping renewed");
        Ok(())
    }

    /// Delete the mapping from the gateway.
    ///
    /// # Errors
    /// Fails if the gateway refuses or is unreachable.
    pub async fn remove(&self) -> Result<()> {
        self.gateway
            .remove_port(PortMappingProtocol::UDP, self.external.port())
            .await
            .map_err(|e| HermesError::Nat(format!("UPnP remove: {e}")))?;
        info!(external = %self.external, "UPnP mapping removed");
        Ok(())
    }
}

/// Map `internal_ip:internal_port` (UDP) on the gateway, preferring the
/// same external port.
///
/// # Errors
/// Fails if no gateway answers, it refuses the mapping, or it reports a
/// non-IPv4 external address.
pub async fn map_udp_port(
    internal_ip: Ipv4Addr,
    internal_port: u16,
    description: &str,
) -> Result<UpnpMapping> {
    if internal_ip.is_unspecified() || internal_port == 0 {
        return Err(HermesError::Nat(
            "UPnP needs a concrete local address".into(),
        ));
    }
    let gateway = search_gateway(SearchOptions {
        timeout: Some(SEARCH_TIMEOUT),
        ..SearchOptions::default()
    })
    .await
    .map_err(|e| HermesError::Nat(format!("UPnP gateway search: {e}")))?;

    let external_ip = match gateway
        .get_external_ip()
        .await
        .map_err(|e| HermesError::Nat(format!("UPnP external IP: {e}")))?
    {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => return Err(HermesError::Nat("UPnP gateway reported IPv6".into())),
    };

    let local = SocketAddr::V4(SocketAddrV4::new(internal_ip, internal_port));
    let mut lease_secs = LEASE_SECS;
    let attempt = gateway
        .add_port(
            PortMappingProtocol::UDP,
            internal_port,
            local,
            lease_secs,
            description,
        )
        .await;
    if let Err(e) = attempt {
        debug!(?e, "UPnP finite lease refused — retrying indefinite");
        lease_secs = 0;
        gateway
            .add_port(
                PortMappingProtocol::UDP,
                internal_port,
                local,
                0,
                description,
            )
            .await
            .map_err(|e| HermesError::Nat(format!("UPnP add_port: {e}")))?;
    }
    info!(%external_ip, port = internal_port, lease_secs, "UPnP mapping created");
    Ok(UpnpMapping {
        gateway,
        external: SocketAddrV4::new(external_ip, internal_port),
        local,
        lease_secs,
        description: description.to_string(),
    })
}
