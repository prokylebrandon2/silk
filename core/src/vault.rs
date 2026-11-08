//! Shared types (`Entry`, `Kdf`, key derivation) and the **legacy** `.pvlt` vault container.
//!
//! `Vault` is the format Silk used before the key slot existed: the Argon2id key encrypts the entries
//! directly. New vaults use `cloud::CloudVault` (VEK + key slot + archive). `Vault` stays so that old
//! vaults and old backups can still be opened and converted (`CloudVault::migrate_legacy`), and
//! because the browser extension reads this format. The `PVLT` magic is the old format's identity
//! and is deliberately not renamed: old files must keep being recognised.
use crate::error::Error;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 4] = b"PVLT";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 31;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

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

/// Plain but authenticated header: "PVLT" | version | flags | t | memKiB | p | salt[16].
/// File = header | nonce[12] | AES-256-GCM(ciphertext + tag); the header is bound in as associated data.
struct Header {
    key_file: bool,
    kdf: Kdf,
    salt: [u8; 16],
}

impl Header {
    fn to_bytes(&self) -> [u8; HEADER_LEN] {
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

    fn parse(f: &[u8]) -> Result<Header, Error> {
        if f.len() < HEADER_LEN + NONCE_LEN + TAG_LEN || &f[0..4] != MAGIC || f[4] != VERSION {
            return Err(Error::NotAVault);
        }
        let t = u32::from_be_bytes([f[6], f[7], f[8], f[9]]);
        let mem_kib = u32::from_be_bytes([f[10], f[11], f[12], f[13]]);
        let p = u32::from(f[14]);
        // Reject absurd costs so a crafted file can't exhaust memory or hang the app.
        if !(1..=32).contains(&t) || !(8..=(1 << 18)).contains(&mem_kib) || !(1..=16).contains(&p) {
            return Err(Error::Corrupt);
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&f[15..31]);
        Ok(Header {
            key_file: (f[5] & 1) == 1,
            kdf: Kdf { t, mem_kib, p },
            salt,
        })
    }
}

#[derive(Deserialize)]
struct Doc {
    entries: Vec<Entry>,
}

#[derive(Serialize)]
struct DocRef<'a> {
    entries: &'a [Entry],
}

/// An unlocked vault: the derived 256-bit key plus the decrypted entries. Both are wiped on drop.
pub struct Vault {
    header: Header,
    key: Zeroizing<[u8; 32]>,
    pub entries: Vec<Entry>,
}

impl Drop for Vault {
    fn drop(&mut self) {
        for e in self.entries.iter_mut() {
            e.zeroize();
        }
    }
}

impl Vault {
    /// A new, empty vault. `key_file` is mixed into the key when given.
    pub fn create(password: &str, key_file: Option<&[u8]>, kdf: Kdf) -> Result<Vault, Error> {
        let mut salt = [0u8; 16];
        getrandom::getrandom(&mut salt).map_err(|_| Error::Random)?;
        let header = Header {
            key_file: key_file.is_some(),
            kdf,
            salt,
        };
        let key = derive_key(password, key_file, &header)?;
        Ok(Vault {
            header,
            key,
            entries: Vec::new(),
        })
    }

    /// Checks that `file` looks like a vault without needing the password.
    pub fn validate(file: &[u8]) -> Result<(), Error> {
        Header::parse(file).map(|_| ())
    }

    pub fn open(file: &[u8], password: &str, key_file: Option<&[u8]>) -> Result<Vault, Error> {
        let header = Header::parse(file)?;
        if header.key_file && key_file.is_none() {
            return Err(Error::KeyFileRequired);
        }
        if !header.key_file && key_file.is_some() {
            return Err(Error::KeyFileNotUsed);
        }
        let key = derive_key(password, key_file, &header)?;
        Vault::decrypt(file, header, key)
    }

    fn decrypt(file: &[u8], header: Header, key: Zeroizing<[u8; 32]>) -> Result<Vault, Error> {
        // Header::parse already checked the length.
        let (aad, rest) = file.split_at(HEADER_LEN);
        let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
        let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|_| Error::Crypto)?;
        let plain = cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| Error::WrongCredentials)?;
        let plain = Zeroizing::new(plain);
        let doc: Doc = serde_json::from_slice(&plain).map_err(|_| Error::Corrupt)?;
        Ok(Vault {
            header,
            key,
            entries: doc.entries,
        })
    }

    /// Encrypts the current entries with a fresh nonce. Cheap: the key derivation isn't repeated.
    pub fn seal(&self) -> Result<Vec<u8>, Error> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce).map_err(|_| Error::Random)?;
        let aad = self.header.to_bytes();
        let body = serde_json::to_vec(&DocRef {
            entries: &self.entries,
        })
        .map_err(|_| Error::Corrupt)?;
        let body = Zeroizing::new(body);
        let cipher = Aes256Gcm::new_from_slice(&self.key[..]).map_err(|_| Error::Crypto)?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &body[..],
                    aad: &aad[..],
                },
            )
            .map_err(|_| Error::Crypto)?;
        let mut out = Vec::with_capacity(HEADER_LEN + NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&aad);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn upsert(&mut self, e: Entry) {
        match self.entries.iter_mut().find(|x| x.id == e.id) {
            Some(slot) => *slot = e,
            None => self.entries.push(e),
        }
    }

    pub fn remove(&mut self, id: &str) {
        self.entries.retain(|e| e.id != id);
    }
}

/// password -> SHA-256, [then SHA-256(that || SHA-256(key file))] -> Argon2id -> 32-byte key.
fn derive_key(
    password: &str,
    key_file: Option<&[u8]>,
    h: &Header,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    derive_key_raw(password, key_file, h.kdf, &h.salt)
}

/// Same derivation, without a vault header. The key slot that wraps the VEK (see `keyslot`) uses it too.
/// A Silk key file contributes only its secret (see `keyfile::material`), so the sign-in saved
/// inside it can change without changing the key; any other file is hashed whole, as always.
pub(crate) fn derive_key_raw(
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

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    getrandom::getrandom(&mut v).expect("the OS random number generator failed");
    v
}

/// A random 128-bit id as lowercase hex.
pub fn new_id() -> String {
    random_bytes(16)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Uniformly random password from an alphabet without look-alike characters.
pub fn generate_password(len: usize) -> String {
    const CHARS: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#%^&*-_=+";
    let n = CHARS.len() as u32;
    let limit = u32::MAX - (u32::MAX % n); // rejection sampling avoids modulo bias
    let mut out = String::with_capacity(len);
    while out.len() < len {
        let r = random_bytes(4);
        let v = u32::from_le_bytes([r[0], r[1], r[2], r[3]]);
        if v < limit {
            out.push(CHARS[(v % n) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: Kdf = Kdf {
        t: 1,
        mem_kib: 64,
        p: 1,
    };

    fn entry(id: &str, title: &str) -> Entry {
        Entry {
            id: id.into(),
            title: title.into(),
            username: "me".into(),
            password: "pw".into(),
            url: String::new(),
            otp: "JBSWY3DPEHPK3PXP".into(),
            notes: String::new(),
        }
    }

    #[test]
    fn round_trip_with_key_file() {
        let kf = [7u8; 64];
        let mut v = Vault::create("correct horse", Some(&kf), FAST).unwrap();
        v.upsert(entry("1", "GitHub"));
        let bytes = v.seal().unwrap();

        let back = Vault::open(&bytes, "correct horse", Some(&kf)).unwrap();
        assert_eq!(back.entries.len(), 1);
        assert_eq!(back.entries[0].title, "GitHub");
        assert_eq!(back.entries[0].otp, "JBSWY3DPEHPK3PXP");

        assert_eq!(
            Vault::open(&bytes, "wrong", Some(&kf)).err(),
            Some(Error::WrongCredentials)
        );
        assert_eq!(
            Vault::open(&bytes, "correct horse", None).err(),
            Some(Error::KeyFileRequired)
        );
        assert_eq!(
            Vault::open(&bytes, "correct horse", Some(&[0u8; 64])).err(),
            Some(Error::WrongCredentials)
        );

        let mut tampered = bytes.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(
            Vault::open(&tampered, "correct horse", Some(&kf)).err(),
            Some(Error::WrongCredentials)
        );

        // The header is authenticated too: flipping a KDF byte must not decrypt.
        let mut hdr = bytes.clone();
        hdr[9] ^= 1;
        assert!(Vault::open(&hdr, "correct horse", Some(&kf)).is_err());
    }

    #[test]
    fn works_without_key_file_and_rejects_one() {
        let v = Vault::create("password1", None, FAST).unwrap();
        let bytes = v.seal().unwrap();
        assert!(Vault::open(&bytes, "password1", None).is_ok());
        assert_eq!(
            Vault::open(&bytes, "password1", Some(&[1u8; 8])).err(),
            Some(Error::KeyFileNotUsed)
        );
    }

    #[test]
    fn every_save_uses_a_fresh_nonce() {
        let v = Vault::create("password1", None, FAST).unwrap();
        assert_ne!(v.seal().unwrap(), v.seal().unwrap());
    }

    #[test]
    fn upsert_replaces_and_remove_deletes() {
        let mut v = Vault::create("password1", None, FAST).unwrap();
        v.upsert(entry("1", "A"));
        v.upsert(entry("1", "B"));
        assert_eq!(v.entries.len(), 1);
        assert_eq!(v.entries[0].title, "B");
        v.remove("1");
        assert!(v.entries.is_empty());
    }

    #[test]
    fn rejects_garbage_and_absurd_costs() {
        assert_eq!(
            Vault::validate(b"not a vault").err(),
            Some(Error::NotAVault)
        );
        let v = Vault::create("password1", None, FAST).unwrap();
        let mut bytes = v.seal().unwrap();
        bytes[10..14].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(Vault::validate(&bytes).err(), Some(Error::Corrupt));
    }

    #[test]
    fn generated_passwords_have_the_right_length_and_vary() {
        let a = generate_password(24);
        assert_eq!(a.len(), 24);
        assert_ne!(a, generate_password(24));
        assert_eq!(new_id().len(), 32);
    }
}
