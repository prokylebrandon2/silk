//! One saved login, and the random ids that name them.
use crate::generator::random_bytes;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// One saved login.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub struct Entry {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub otp: String,
    #[serde(default)]
    pub notes: String,
}

/// A random 128-bit id as lowercase hex.
pub fn new_id() -> String {
    random_bytes(16)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_32_hex_characters_and_differ() {
        let a = new_id();
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, new_id());
    }
}
