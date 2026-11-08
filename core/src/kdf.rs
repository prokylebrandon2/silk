//! Key derivation: the Argon2id key that wraps the VEK (see `keyslot`).
use crate::error::Error;
use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Argon2id cost. The defaults follow RFC 9106's low-memory profile (t=3, 64 MiB, p=4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kdf {
    pub t: u32,
    pub mem_kib: u32,
    pub p: u32,
}

impl Default for Kdf {
    fn default() -> Self {
        Kdf {
            t: 3,
            mem_kib: 65536,
            p: 4,
        }
    }
}

impl Kdf {
    /// Rejects absurd costs so a crafted file can't exhaust memory or hang the app.
    pub(crate) fn is_sane(&self) -> bool {
        (1..=32).contains(&self.t)
            && (8..=(1 << 18)).contains(&self.mem_kib)
            && (1..=16).contains(&self.p)
    }
}

/// password -> SHA-256, [then SHA-256(that || SHA-256(key file))] -> Argon2id -> 32-byte key.
///
/// A Silk key file contributes only its secret (see `keyfile::material`), so the sign-in saved
/// inside it can change without changing the key; any other file is hashed whole.
pub(crate) fn derive_key(
    password: &str,
    key_file: Option<&[u8]>,
    kdf: Kdf,
    salt: &[u8; 16],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut ikm = Zeroizing::new([0u8; 32]);
    ikm.copy_from_slice(&Sha256::digest(password.as_bytes()));
    if let Some(kf) = key_file {
        let mut hasher = Sha256::new();
        hasher.update(&ikm[..]);
        hasher.update(Sha256::digest(crate::keyfile::material(kf)));
        ikm.copy_from_slice(&hasher.finalize());
    }
    let params = Params::new(kdf.mem_kib, kdf.t, kdf.p, Some(32)).map_err(|_| Error::Corrupt)?;
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(&ikm[..], salt, &mut out[..])
        .map_err(|_| Error::Crypto)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: Kdf = Kdf {
        t: 1,
        mem_kib: 64,
        p: 1,
    };

    #[test]
    fn the_key_depends_on_password_key_file_and_salt() {
        let salt = [5u8; 16];
        let base = derive_key("password1", None, FAST, &salt).unwrap();
        assert_eq!(*base, *derive_key("password1", None, FAST, &salt).unwrap());
        assert_ne!(*base, *derive_key("password2", None, FAST, &salt).unwrap());
        assert_ne!(*base, *derive_key("password1", Some(&[1u8; 8]), FAST, &salt).unwrap());
        assert_ne!(*base, *derive_key("password1", None, FAST, &[6u8; 16]).unwrap());
    }

    #[test]
    fn absurd_costs_are_not_sane() {
        assert!(Kdf::default().is_sane());
        assert!(!Kdf { t: 0, ..FAST }.is_sane());
        assert!(!Kdf { mem_kib: u32::MAX, ..FAST }.is_sane());
        assert!(!Kdf { p: 17, ..FAST }.is_sane());
    }
}
