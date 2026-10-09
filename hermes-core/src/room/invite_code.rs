//! Human-readable, checksummed room invite codes.
//!
//! An invite code is 12 characters from a 32-symbol alphabet, displayed
//! in three dash-separated groups: `K7QF-M2XA-9RTB`. The first 11
//! characters are random (55 bits — far too many to enumerate against a
//! rate-limited signaling server); the 12th is a Luhn mod 32 check
//! character, so any single mistyped character and every swap of two
//! adjacent characters but one (`A`↔`9`, the values 0 and 31 — the known
//! blind spot of Luhn mod N) is caught locally before the code is ever
//! sent to the server. The check is a typo aid, not a security feature:
//! secrecy rests on the 55 random bits, and the server rate-limits guesses.
//!
//! The alphabet drops `I`, `O`, `0` and `1`, the glyphs people confuse
//! when reading a code aloud or copying it off a screen. Parsing is
//! case-insensitive and ignores dashes and whitespace.

use std::fmt;
use std::str::FromStr;

use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::error::HermesError;

/// The 32 symbols, indexed by value.
const ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
/// Total characters in a code (excluding dashes).
const CODE_LEN: usize = 12;
/// Random characters preceding the check character.
const PAYLOAD_LEN: usize = CODE_LEN - 1;

/// A validated invite code. Stored as its 12 symbol values.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct InviteCode([u8; CODE_LEN]);

fn symbol_value(c: char) -> Option<u8> {
    let up = c.to_ascii_uppercase();
    let byte = u8::try_from(up).ok()?;
    ALPHABET
        .iter()
        .position(|&a| a == byte)
        .and_then(|p| u8::try_from(p).ok())
}

/// Luhn mod N check value over `values` (N = 32).
fn luhn_check(values: &[u8]) -> u8 {
    const N: u32 = 32;
    let mut sum: u32 = 0;
    // Double every second value starting from the rightmost payload
    // symbol, as in classic Luhn.
    for (i, &v) in values.iter().rev().enumerate() {
        let mut addend = u32::from(v);
        if i % 2 == 0 {
            addend *= 2;
            addend = addend / N + addend % N;
        }
        sum += addend;
    }
    let check = (N - sum % N) % N;
    u8::try_from(check).expect("check < 32")
}

impl InviteCode {
    /// Generate a fresh random code.
    #[must_use]
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let mut values = [0u8; CODE_LEN];
        for v in &mut values[..PAYLOAD_LEN] {
            *v = rng.gen_range(0..32);
        }
        values[PAYLOAD_LEN] = luhn_check(&values[..PAYLOAD_LEN]);
        Self(values)
    }

    fn is_valid(values: &[u8; CODE_LEN]) -> bool {
        luhn_check(&values[..PAYLOAD_LEN]) == values[PAYLOAD_LEN]
    }
}

impl fmt::Display for InviteCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, &v) in self.0.iter().enumerate() {
            if i > 0 && i % 4 == 0 {
                f.write_str("-")?;
            }
            write!(f, "{}", char::from(ALPHABET[usize::from(v)]))?;
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

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut values = [0u8; CODE_LEN];
        let mut n = 0;
        for c in s.chars() {
            if c == '-' || c.is_whitespace() {
                continue;
            }
            if n == CODE_LEN {
                return Err(HermesError::InvalidInviteCode);
            }
            values[n] = symbol_value(c).ok_or(HermesError::InvalidInviteCode)?;
            n += 1;
        }
        if n != CODE_LEN || !Self::is_valid(&values) {
            return Err(HermesError::InvalidInviteCode);
        }
        Ok(Self(values))
    }
}

impl Serialize for InviteCode {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for InviteCode {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let s = String::deserialize(d)?;
        s.parse()
            .map_err(|_| D::Error::custom("invalid invite code"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_codes_roundtrip() {
        for _ in 0..200 {
            let code = InviteCode::generate();
            let text = code.to_string();
            assert_eq!(text.len(), 14);
            assert_eq!(text.as_bytes()[4], b'-');
            assert_eq!(text.as_bytes()[9], b'-');
            assert_eq!(text.parse::<InviteCode>().unwrap(), code);
        }
    }

    #[test]
    fn documented_example_code_is_valid() {
        // Used in the UI placeholder, README and TEST-RUN.md.
        assert!("WLFK-7X4K-QR2S".parse::<InviteCode>().is_ok());
    }

    #[test]
    fn parsing_is_lenient_about_case_and_separators() {
        let code = InviteCode::generate();
        let sloppy = code.to_string().to_lowercase().replace('-', " ");
        assert_eq!(sloppy.parse::<InviteCode>().unwrap(), code);
        let packed = code.to_string().replace('-', "");
        assert_eq!(packed.parse::<InviteCode>().unwrap(), code);
    }

    #[test]
    fn every_single_substitution_is_detected() {
        let code = InviteCode::generate();
        for pos in 0..CODE_LEN {
            for v in 0..32u8 {
                if v == code.0[pos] {
                    continue;
                }
                let mut bad = code.0;
                bad[pos] = v;
                assert!(!InviteCode::is_valid(&bad), "missed substitution at {pos}");
            }
        }
    }

    #[test]
    fn adjacent_swaps_are_detected_except_the_known_blind_spot() {
        // Exhaustive over symbol pairs and positions for a fixed prefix.
        let mut undetected = Vec::new();
        for seed in 0..50u8 {
            let mut values = [0u8; CODE_LEN];
            for (i, v) in values[..PAYLOAD_LEN].iter_mut().enumerate() {
                *v = seed
                    .wrapping_mul(7)
                    .wrapping_add(u8::try_from(i * 5).unwrap())
                    % 32;
            }
            values[PAYLOAD_LEN] = luhn_check(&values[..PAYLOAD_LEN]);
            for pos in 0..CODE_LEN - 1 {
                if values[pos] == values[pos + 1] {
                    continue;
                }
                let mut swapped = values;
                swapped.swap(pos, pos + 1);
                if InviteCode::is_valid(&swapped) {
                    let pair = (
                        values[pos].min(values[pos + 1]),
                        values[pos].max(values[pos + 1]),
                    );
                    undetected.push(pair);
                }
            }
        }
        assert!(
            undetected.iter().all(|&pair| pair == (0, 31)),
            "only the A<->9 swap may slip through, got {undetected:?}"
        );
    }

    #[test]
    fn rejects_wrong_length_and_bad_symbols() {
        assert!("".parse::<InviteCode>().is_err());
        assert!("ABCD-EFGH-JKL".parse::<InviteCode>().is_err());
        assert!("ABCD-EFGH-JKLMN".parse::<InviteCode>().is_err());
        // 'O', '0', 'I', '1' are not in the alphabet.
        assert!("OOOO-0000-IIII".parse::<InviteCode>().is_err());
    }

    #[test]
    fn serde_is_a_string() {
        let code = InviteCode::generate();
        let json = serde_json::to_string(&code).unwrap();
        assert_eq!(json, format!("\"{code}\""));
        assert_eq!(serde_json::from_str::<InviteCode>(&json).unwrap(), code);
        assert!(serde_json::from_str::<InviteCode>("\"nope\"").is_err());
    }
}
