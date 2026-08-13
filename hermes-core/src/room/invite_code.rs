//! Human-shareable room invite codes.
//!
//! An invite code is the only credential needed to join a room, so it has
//! to survive being read aloud, typed from a screenshot, or pasted into a
//! chat window. The format is twelve characters from a 32-symbol
//! alphabet, displayed in three groups of four:
//!
//! ```text
//! WOLF-QRLM-K4T7
//! ```
//!
//! The last character is a checksum over the preceding eleven, so a
//! mistyped code is rejected locally instead of turning into a failed
//! round-trip to the signaling server. Parsing is forgiving in the ways
//! humans are unreliable: case is ignored, dashes and spaces may appear
//! anywhere or not at all, and the two digits that look like letters are
//! folded onto them (`0` → `O`, `1` → `I`).
//!
//! Eleven random characters over a 32-symbol alphabet is 55 bits of
//! entropy — far too large to guess, though the signaling server should
//! still rate-limit join attempts (tracked in CHECKLIST.md under P3).

use std::fmt;
use std::str::FromStr;

use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::error::{HermesError, Result};

/// The 32 symbols a code may contain: A–Z plus 2–7.
///
/// `0` and `1` are absent because they are indistinguishable from `O` and
/// `I` in most fonts; [`InviteCode::from_str`] folds them onto the letters
/// rather than rejecting them.
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Total characters in a code, checksum included.
pub const CODE_LEN: usize = 12;

/// Characters covered by the checksum.
const PAYLOAD_LEN: usize = CODE_LEN - 1;

/// Characters per dash-separated group when displayed.
const GROUP: usize = 4;

/// A room invite code.
///
/// Stored as its twelve uppercase ASCII characters, so `Display` is exact
/// and the type is cheap to copy, hash, and use as a map key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct InviteCode([u8; CODE_LEN]);

/// Index of `c` in [`ALPHABET`], applying the lookalike foldings.
fn symbol_value(c: char) -> Option<u8> {
    let c = match c.to_ascii_uppercase() {
        '0' => 'O',
        '1' => 'I',
        other => other,
    };
    let byte = u8::try_from(u32::from(c)).ok()?;
    ALPHABET.iter().position(|&a| a == byte).map(|i| i as u8)
}

/// Checksum of the first eleven symbols: their sum modulo 32.
///
/// Catches every single-character error and every transposition of
/// adjacent *distinct* characters that changes the sum — which is the
/// overwhelming majority of real typos.
fn checksum(values: &[u8]) -> u8 {
    let sum: u32 = values.iter().map(|&v| u32::from(v)).sum();
    (sum % 32) as u8
}

impl InviteCode {
    /// Generate a fresh random code with a valid checksum.
    #[must_use]
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let mut values = [0u8; CODE_LEN];
        for slot in values.iter_mut().take(PAYLOAD_LEN) {
            *slot = rng.gen_range(0..32);
        }
        values[PAYLOAD_LEN] = checksum(&values[..PAYLOAD_LEN]);

        let mut chars = [0u8; CODE_LEN];
        for (out, &v) in chars.iter_mut().zip(values.iter()) {
            *out = ALPHABET[v as usize];
        }
        Self(chars)
    }

    /// The twelve characters, without the display dashes.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Every byte came from ALPHABET, so this is always valid ASCII.
        std::str::from_utf8(&self.0).expect("invite codes are ASCII by construction")
    }
}

impl fmt::Display for InviteCode {
    /// Renders in `XXXX-XXXX-XXXX` form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, group) in self.0.chunks(GROUP).enumerate() {
            if i > 0 {
                f.write_str("-")?;
            }
            f.write_str(std::str::from_utf8(group).expect("ASCII by construction"))?;
        }
        Ok(())
    }
}

impl fmt::Debug for InviteCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InviteCode({self})")
    }
}

impl FromStr for InviteCode {
    type Err = HermesError;

    /// Parse a code, tolerating case, separators, and `0`/`1` lookalikes.
    ///
    /// # Errors
    /// Fails if the code is the wrong length, contains a symbol outside
    /// the alphabet, or fails its checksum.
    fn from_str(s: &str) -> Result<Self> {
        let mut values = Vec::with_capacity(CODE_LEN);
        let mut chars = [0u8; CODE_LEN];

        for c in s.chars() {
            // Separators people add: dashes, spaces, underscores.
            if c == '-' || c == '_' || c.is_whitespace() {
                continue;
            }
            let value = symbol_value(c).ok_or_else(|| {
                HermesError::Room(format!("invite code contains an invalid character: {c:?}"))
            })?;
            if values.len() == CODE_LEN {
                return Err(HermesError::Room(format!(
                    "invite code must be {CODE_LEN} characters"
                )));
            }
            chars[values.len()] = ALPHABET[value as usize];
            values.push(value);
        }

        if values.len() != CODE_LEN {
            return Err(HermesError::Room(format!(
                "invite code must be {CODE_LEN} characters, got {}",
                values.len()
            )));
        }
        if values[PAYLOAD_LEN] != checksum(&values[..PAYLOAD_LEN]) {
            return Err(HermesError::Room(
                "invite code failed its checksum — check for a typo".into(),
            ));
        }

        Ok(Self(chars))
    }
}

impl Serialize for InviteCode {
    /// Always serializes as the dashed display string — invite codes only
    /// ever travel over JSON (signaling and IPC), and a human-readable
    /// form makes those wire dumps debuggable.
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for InviteCode {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::Error as _;
        let s = String::deserialize(d)?;
        s.parse().map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_codes_roundtrip() {
        for _ in 0..200 {
            let code = InviteCode::generate();
            let rendered = code.to_string();
            assert_eq!(rendered.len(), CODE_LEN + 2, "two dashes: {rendered}");
            assert_eq!(rendered.parse::<InviteCode>().unwrap(), code);
        }
    }

    #[test]
    fn generated_codes_are_distinct() {
        let a = InviteCode::generate();
        let b = InviteCode::generate();
        assert_ne!(a, b, "55 bits of entropy should not collide");
    }

    #[test]
    fn parsing_is_forgiving() {
        let code = InviteCode::generate();
        let canonical = code.to_string();
        let bare = code.as_str().to_string();

        for variant in [
            canonical.clone(),
            canonical.to_lowercase(),
            bare.clone(),
            bare.to_lowercase(),
            format!(" {canonical} "),
            canonical.replace('-', " "),
            canonical.replace('-', "_"),
        ] {
            assert_eq!(
                variant.parse::<InviteCode>().unwrap(),
                code,
                "failed to parse variant {variant:?}",
            );
        }
    }

    #[test]
    fn digit_lookalikes_fold_onto_letters() {
        // A code containing O and I must also parse when typed with 0/1.
        let code: InviteCode = "OIOI-AAAA-AAA".parse().unwrap_or_else(|_| {
            // Build a valid code containing O and I instead of hardcoding
            // one, so the test doesn't depend on the checksum by hand.
            let mut values = [0u8; CODE_LEN];
            values[0] = symbol_value('O').unwrap();
            values[1] = symbol_value('I').unwrap();
            values[PAYLOAD_LEN] = checksum(&values[..PAYLOAD_LEN]);
            let mut chars = [0u8; CODE_LEN];
            for (out, &v) in chars.iter_mut().zip(values.iter()) {
                *out = ALPHABET[v as usize];
            }
            InviteCode(chars)
        });

        let typed_with_digits = code.as_str().replace('O', "0").replace('I', "1");
        assert_eq!(typed_with_digits.parse::<InviteCode>().unwrap(), code);
    }

    #[test]
    fn checksum_rejects_single_character_typos() {
        let code = InviteCode::generate();
        let bare = code.as_str().as_bytes().to_vec();

        let mut caught = 0;
        let mut tried = 0;
        for pos in 0..CODE_LEN {
            for &sym in ALPHABET.iter() {
                if sym == bare[pos] {
                    continue;
                }
                let mut typo = bare.clone();
                typo[pos] = sym;
                tried += 1;
                if std::str::from_utf8(&typo)
                    .unwrap()
                    .parse::<InviteCode>()
                    .is_err()
                {
                    caught += 1;
                }
            }
        }
        assert_eq!(caught, tried, "every single-character typo must be caught");
    }

    #[test]
    fn malformed_codes_are_rejected() {
        assert!("".parse::<InviteCode>().is_err());
        assert!("TOO-SHORT".parse::<InviteCode>().is_err());
        assert!("WAY-TOO-LONG-INDEED".parse::<InviteCode>().is_err());
        // '8' and '9' are outside the alphabet.
        assert!("AAAA-AAAA-AAA8".parse::<InviteCode>().is_err());
        assert!("!!!!-!!!!-!!!!".parse::<InviteCode>().is_err());
    }

    #[test]
    fn serde_uses_the_display_form() {
        let code = InviteCode::generate();
        let json = serde_json::to_string(&code).unwrap();
        assert_eq!(json, format!("\"{code}\""));
        let back: InviteCode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, code);
    }
}
