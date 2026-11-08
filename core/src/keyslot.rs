//! The key slot: where the Argon2id key meets the VEK.
//!
//! The vault data (`.skln`) is encrypted with a random 256-bit **VEK** (Vault Encryption Key). The
//! VEK never leaves the device in the clear. What goes to the cloud next to the `.skln` is the
//! VEK encrypted ("wrapped") with a key derived from the master password (and key file) by
//! Argon2id:
//!
//! ```text
//! "SKVK" | version u8 | flags u8 | t u32 | memKiB u32 | p u8 | salt[16] | nonce[12] | AES-256-GCM(VEK) + tag[16]
//! ```
//!
//! The first 31 bytes (everything up to and including the salt) are the associated data. A slot is
//! 91 bytes. Because the VEK is separate from the password, changing the password only re-wraps
//! the VEK: the big `.skln` file isn't touched.
use crate::error::Error;
use crate::kdf::{derive_key, Kdf};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"SKVK";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 31;
const NONCE_LEN: usize = 12;
const WRAPPED_LEN: usize = 32 + 16;
pub const KEYSLOT_LEN: usize = HEADER_LEN + NONCE_LEN + WRAPPED_LEN;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeySlot {
    key_file: bool,
    kdf: Kdf,
    salt: [u8; 16],
    nonce: [u8; NONCE_LEN],
    wrapped: [u8; WRAPPED_LEN],
}

impl KeySlot {
    /// First-time setup: draws a random VEK and wraps it. Returns the slot and the VEK.
    pub fn create(
        password: &str,
        key_file: Option<&[u8]>,
        kdf: Kdf,
    ) -> Result<(KeySlot, Zeroizing<[u8; 32]>), Error> {
        let mut vek = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(&mut vek[..]).map_err(|_| Error::Random)?;
        let slot = KeySlot::wrap(&vek, password, key_file, kdf)?;
        Ok((slot, vek))
    }

    /// Wraps an existing VEK under new credentials, with a fresh salt and nonce.
    pub fn wrap(
        vek: &[u8; 32],
        password: &str,
        key_file: Option<&[u8]>,
        kdf: Kdf,
    ) -> Result<KeySlot, Error> {
        if !kdf.is_sane() {
            return Err(Error::Corrupt);
        }
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut salt).map_err(|_| Error::Random)?;
        getrandom::getrandom(&mut nonce).map_err(|_| Error::Random)?;
        let kek = derive_key(password, key_file, kdf, &salt)?;
        let mut slot = KeySlot {
            key_file: key_file.is_some(),
            kdf,
            salt,
            nonce,
            wrapped: [0u8; WRAPPED_LEN],
        };
        let aad = slot.header_bytes();
        let cipher = Aes256Gcm::new_from_slice(&kek[..]).map_err(|_| Error::Crypto)?;
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &vek[..],
                    aad: &aad[..],
                },
            )
            .map_err(|_| Error::Crypto)?;
        if ct.len() != WRAPPED_LEN {
            return Err(Error::Crypto);
        }
        slot.wrapped.copy_from_slice(&ct);
        Ok(slot)
    }

    /// Subsequent unlock: derives the key with Argon2id and decrypts the VEK.
    pub fn unwrap(
        &self,
        password: &str,
        key_file: Option<&[u8]>,
    ) -> Result<Zeroizing<[u8; 32]>, Error> {
        if self.key_file && key_file.is_none() {
            return Err(Error::KeyFileRequired);
        }
        if !self.key_file && key_file.is_some() {
            return Err(Error::KeyFileNotUsed);
        }
        let kek = derive_key(password, key_file, self.kdf, &self.salt)?;
        let aad = self.header_bytes();
        let cipher = Aes256Gcm::new_from_slice(&kek[..]).map_err(|_| Error::Crypto)?;
        let plain = cipher
            .decrypt(
                Nonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.wrapped[..],
                    aad: &aad[..],
                },
            )
            .map_err(|_| Error::WrongCredentials)?;
        let plain = Zeroizing::new(plain);
        if plain.len() != 32 {
            return Err(Error::Corrupt);
        }
        let mut vek = Zeroizing::new([0u8; 32]);
        vek.copy_from_slice(&plain);
        Ok(vek)
    }

    pub fn uses_key_file(&self) -> bool {
        self.key_file
    }

    pub fn kdf(&self) -> Kdf {
        self.kdf
    }

    fn header_bytes(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0..4].copy_from_slice(MAGIC);
        b[4] = VERSION;
        b[5] = u8::from(self.key_file);
        b[6..10].copy_from_slice(&self.kdf.t.to_be_bytes());
        b[10..14].copy_from_slice(&self.kdf.mem_kib.to_be_bytes());
        b[14] = self.kdf.p as u8;
        b[15..31].copy_from_slice(&self.salt);
        b
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(KEYSLOT_LEN);
        out.extend_from_slice(&self.header_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.wrapped);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<KeySlot, Error> {
        if b.len() != KEYSLOT_LEN || &b[0..4] != MAGIC || b[4] != VERSION {
            return Err(Error::NotAVault);
        }
        let kdf = Kdf {
            t: u32::from_be_bytes([b[6], b[7], b[8], b[9]]),
            mem_kib: u32::from_be_bytes([b[10], b[11], b[12], b[13]]),
            p: u32::from(b[14]),
        };
        // Reject absurd costs so a crafted slot can't exhaust memory or hang the app.
        if !kdf.is_sane() {
            return Err(Error::Corrupt);
        }
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; NONCE_LEN];
        let mut wrapped = [0u8; WRAPPED_LEN];
        salt.copy_from_slice(&b[15..31]);
        nonce.copy_from_slice(&b[31..43]);
        wrapped.copy_from_slice(&b[43..91]);
        Ok(KeySlot {
            key_file: (b[5] & 1) == 1,
            kdf,
            salt,
            nonce,
            wrapped,
        })
    }
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
    fn create_then_unwrap_gives_the_same_vek() {
        let (slot, vek) = KeySlot::create("correct horse", None, FAST).unwrap();
        let back = slot.unwrap("correct horse", None).unwrap();
        assert_eq!(&back[..], &vek[..]);
        assert_eq!(slot.to_bytes().len(), KEYSLOT_LEN);
    }

    #[test]
    fn wrong_password_and_key_file_mismatches_are_rejected() {
        let kf = [5u8; 64];
        let (slot, _) = KeySlot::create("password1", Some(&kf), FAST).unwrap();
        assert_eq!(
            slot.unwrap("wrong", Some(&kf)).err(),
            Some(Error::WrongCredentials)
        );
        assert_eq!(
            slot.unwrap("password1", None).err(),
            Some(Error::KeyFileRequired)
        );
        assert_eq!(
            slot.unwrap("password1", Some(&[0u8; 64])).err(),
            Some(Error::WrongCredentials)
        );
        let (plain, _) = KeySlot::create("password1", None, FAST).unwrap();
        assert_eq!(
            plain.unwrap("password1", Some(&kf)).err(),
            Some(Error::KeyFileNotUsed)
        );
    }

    #[test]
    fn rewrapping_keeps_the_vek_and_replaces_the_credentials() {
        let (slot, vek) = KeySlot::create("old password", None, FAST).unwrap();
        let moved = KeySlot::wrap(&vek, "new password", None, FAST).unwrap();
        assert_ne!(slot.to_bytes(), moved.to_bytes());
        assert_eq!(&moved.unwrap("new password", None).unwrap()[..], &vek[..]);
        assert_eq!(
            moved.unwrap("old password", None).err(),
            Some(Error::WrongCredentials)
        );
    }

    #[test]
    fn bytes_round_trip_and_tampering_is_detected() {
        let (slot, vek) = KeySlot::create("password1", None, FAST).unwrap();
        let bytes = slot.to_bytes();
        let parsed = KeySlot::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, slot);
        assert_eq!(&parsed.unwrap("password1", None).unwrap()[..], &vek[..]);

        // The header is authenticated: flipping a salt byte must not unwrap.
        let mut salt = bytes.clone();
        salt[20] ^= 1;
        assert_eq!(
            KeySlot::from_bytes(&salt)
                .unwrap()
                .unwrap("password1", None)
                .err(),
            Some(Error::WrongCredentials)
        );
        // So is the wrapped key itself.
        let mut body = bytes.clone();
        let last = body.len() - 1;
        body[last] ^= 1;
        assert_eq!(
            KeySlot::from_bytes(&body)
                .unwrap()
                .unwrap("password1", None)
                .err(),
            Some(Error::WrongCredentials)
        );
    }

    #[test]
    fn from_bytes_rejects_garbage_and_absurd_costs() {
        assert_eq!(KeySlot::from_bytes(b"short").err(), Some(Error::NotAVault));
        let (slot, _) = KeySlot::create("password1", None, FAST).unwrap();
        let mut b = slot.to_bytes();
        b[10..14].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(KeySlot::from_bytes(&b).err(), Some(Error::Corrupt));
        assert_eq!(
            KeySlot::wrap(
                &[0u8; 32],
                "x",
                None,
                Kdf {
                    t: 0,
                    mem_kib: 64,
                    p: 1
                }
            )
            .err(),
            Some(Error::Corrupt)
        );
    }
}
