//! Remembering the last room across restarts.
//!
//! A VPN you have to re-join by hand after every reboot isn't much of a
//! VPN. The daemon records which room it is in (signaling URL + invite
//! code) in `resume.json` and, when it starts, rejoins it.
//!
//! The file holds an invite code (and the room password, if any), which is all it takes to be in the room,
//! so it is created readable by its owner only. It is written when a room
//! is entered and removed on an explicit `leave`, when the user connects
//! somewhere else, or when rejoining fails because the room no longer
//! exists. A plain daemon shutdown deliberately leaves it in place —
//! that's the whole point.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const FILE: &str = "resume.json";

/// What to rejoin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resume {
    /// Signaling server the room lives on.
    pub signaling_url: String,
    /// The room's invite code.
    pub invite_code: String,
    /// The room password, if it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

/// The on-disk record.
#[derive(Clone, Debug)]
pub struct ResumeStore {
    path: PathBuf,
}

impl ResumeStore {
    /// A store keeping its file in `data_dir`.
    #[must_use]
    pub fn new(data_dir: &Path) -> Self {
        Self {
            path: data_dir.join(FILE),
        }
    }

    /// The saved room, if any (an unreadable or corrupt file counts as none).
    #[must_use]
    pub fn load(&self) -> Option<Resume> {
        serde_json::from_slice(&std::fs::read(&self.path).ok()?).ok()
    }

    /// Record `resume`, replacing any previous record.
    ///
    /// # Errors
    /// Fails if the file can't be written.
    pub fn save(&self, resume: &Resume) -> std::io::Result<()> {
        use std::io::Write;
        // Write a sibling first and rename, so a crash never leaves a
        // half-written file; create it private from the start.
        let tmp = self.path.with_extension("json.tmp");
        let _ = std::fs::remove_file(&tmp);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let json = serde_json::to_vec_pretty(resume)?;
        options.open(&tmp)?.write_all(&json)?;
        std::fs::rename(&tmp, &self.path)
    }

    /// Forget the saved room.
    pub fn clear(&self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("hermes-resume-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn save_load_clear() {
        let d = dir("roundtrip");
        let store = ResumeStore::new(&d);
        assert_eq!(store.load(), None);
        let r = Resume {
            signaling_url: "wss://s.example/v1".into(),
            invite_code: "WLFK-7X4K-QR2S".into(),
            password: Some("hunter2".into()),
        };
        store.save(&r).unwrap();
        assert_eq!(store.load(), Some(r.clone()));
        // Overwriting works and leaves no temp file behind.
        let r2 = Resume {
            invite_code: "AAAA-BBBB-CCCC".into(),
            ..r
        };
        store.save(&r2).unwrap();
        assert_eq!(store.load(), Some(r2));
        assert!(!d.join("resume.json.tmp").exists());
        store.clear();
        assert_eq!(store.load(), None);
        store.clear(); // clearing nothing is fine
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn corrupt_file_is_treated_as_empty() {
        let d = dir("corrupt");
        std::fs::write(d.join("resume.json"), b"{not json").unwrap();
        assert_eq!(ResumeStore::new(&d).load(), None);
        let _ = std::fs::remove_dir_all(d);
    }

    #[cfg(unix)]
    #[test]
    fn file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let d = dir("private");
        let store = ResumeStore::new(&d);
        store
            .save(&Resume {
                signaling_url: "ws://x".into(),
                invite_code: "C".into(),
                password: None,
            })
            .unwrap();
        let mode = std::fs::metadata(d.join("resume.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(d);
    }
}
