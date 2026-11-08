//! The Silk key file: a secret that goes into the key derivation, plus the cloud sign-in that Silk
//! saves next to it automatically.
//!
//! ```text
//! "SKEY" | version u8 | secret[64] | login_len u32 | login JSON (login_len bytes)      (login part optional)
//! ```
//!
//! **Only the 64-byte secret feeds Argon2id** (see [`material`]). Everything after it can change
//! freely, so saving or removing the sign-in never changes the key and never locks the vault.
//! Files that don't start with `SKEY` (any file the user picked, and the plain 64-byte files older
//! versions created) are *raw* key files: they are hashed whole, exactly as before, and nothing is
//! ever written into them.
//!
//! The login is the cloud account's email, user id and refresh token. The account password is
//! never stored. A damaged or missing login part is ignored: the secret, which is the part that
//! matters, is always read from the fixed-size head. Later the whole file is meant to be sealed
//! inside Kiln's `.skln`; that layer wraps these bytes as they are.
use crate::error::Error;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MAGIC: &[u8; 4] = b"SKEY";
const VERSION: u8 = 1;
pub const SECRET_LEN: usize = 64;
/// Magic, version and secret: the part that is never rewritten once the file exists.
pub const HEAD_LEN: usize = 4 + 1 + SECRET_LEN;
/// A login JSON larger than this is treated as damaged.
const LOGIN_LIMIT: usize = 16 * 1024;

/// The saved cloud sign-in. The refresh token lets the app get new access tokens without asking for the password.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Login {
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub uid: String,
    #[serde(default)]
    pub refresh_token: String,
}

impl fmt::Debug for Login {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Login")
            .field("email", &self.email)
            .field("uid", &self.uid)
            .field("refresh_token", &"<hidden>")
            .finish()
    }
}

#[derive(Clone)]
pub struct KeyFile {
    secret: Zeroizing<[u8; SECRET_LEN]>,
    login: Option<Login>,
}

/// True when `bytes` is a Silk key file (as opposed to a raw one).
pub fn is_silk_key_file(bytes: &[u8]) -> bool {
    bytes.len() >= HEAD_LEN && &bytes[0..4] == MAGIC && bytes[4] == VERSION
}

/// The bytes that go into the key derivation: the secret of a Silk key file, or a raw file as a whole.
pub fn material(file: &[u8]) -> &[u8] {
    if is_silk_key_file(file) {
        &file[5..HEAD_LEN]
    } else {
        file
    }
}

impl KeyFile {
    /// A new key file with a random secret and no login.
    pub fn generate() -> Result<KeyFile, Error> {
        let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
        getrandom::getrandom(&mut secret[..]).map_err(|_| Error::Random)?;
        Ok(KeyFile {
            secret,
            login: None,
        })
    }

    /// `None` for a raw key file. A damaged login part gives a key file without a login, never an error.
    pub fn parse(bytes: &[u8]) -> Option<KeyFile> {
        if !is_silk_key_file(bytes) {
            return None;
        }
        let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
        secret.copy_from_slice(&bytes[5..HEAD_LEN]);
        Some(KeyFile {
            secret,
            login: parse_login(&bytes[HEAD_LEN..]),
        })
    }

    pub fn secret(&self) -> &[u8; SECRET_LEN] {
        &self.secret
    }

    pub fn login(&self) -> Option<&Login> {
        self.login.as_ref()
    }

    pub fn set_login(&mut self, login: Option<Login>) {
        self.login = login;
    }

    /// The whole file. The first [`HEAD_LEN`] bytes are the same for the life of the key file.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEAD_LEN + 4 + 256);
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&self.secret[..]);
        if let Some(login) = &self.login {
            if let Ok(json) = serde_json::to_vec(login) {
                let json = Zeroizing::new(json);
                if json.len() <= LOGIN_LIMIT {
                    out.extend_from_slice(&(json.len() as u32).to_be_bytes());
                    out.extend_from_slice(&json);
                }
            }
        }
        out
    }
}

fn parse_login(tail: &[u8]) -> Option<Login> {
    if tail.len() < 4 {
        return None;
    }
    let n = u32::from_be_bytes([tail[0], tail[1], tail[2], tail[3]]) as usize;
    if n == 0 || n > LOGIN_LIMIT || tail.len() < 4 + n {
        return None;
    }
    let login: Login = serde_json::from_slice(&tail[4..4 + n]).ok()?;
    if login.refresh_token.is_empty() || login.uid.is_empty() {
        None
    } else {
        Some(login)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::{derive_key, Kdf};

    const FAST: Kdf = Kdf {
        t: 1,
        mem_kib: 64,
        p: 1,
    };

    fn login() -> Login {
        Login {
            email: "me@example.com".into(),
            uid: "u1".into(),
            refresh_token: "r1".into(),
        }
    }

    #[test]
    fn round_trip_with_and_without_a_login() {
        let mut kf = KeyFile::generate().unwrap();
        let bare = kf.to_bytes();
        assert_eq!(bare.len(), HEAD_LEN);
        assert!(is_silk_key_file(&bare));
        assert!(KeyFile::parse(&bare).unwrap().login().is_none());

        kf.set_login(Some(login()));
        let with = kf.to_bytes();
        assert_eq!(KeyFile::parse(&with).unwrap().login(), Some(&login()));
        assert_eq!(&with[..HEAD_LEN], &bare[..]); // the head is untouched

        kf.set_login(None);
        assert_eq!(kf.to_bytes(), bare);
    }

    #[test]
    fn saving_a_login_never_changes_the_key() {
        let mut kf = KeyFile::generate().unwrap();
        let bare = kf.to_bytes();
        kf.set_login(Some(login()));
        let with = kf.to_bytes();
        let salt = [7u8; 16];
        let a = derive_key("password1", Some(&bare), FAST, &salt).unwrap();
        let b = derive_key("password1", Some(&with), FAST, &salt).unwrap();
        assert_eq!(&a[..], &b[..]);
    }

    #[test]
    fn raw_key_files_are_hashed_whole_as_before() {
        let raw = [9u8; 64];
        assert!(!is_silk_key_file(&raw));
        assert!(KeyFile::parse(&raw).is_none());
        assert_eq!(material(&raw), &raw[..]);

        // A Silk key file whose secret equals a raw 64-byte file gives the same key as that raw file.
        let mut silk = Vec::from(&b"SKEY"[..]);
        silk.push(VERSION);
        silk.extend_from_slice(&raw);
        let salt = [3u8; 16];
        let from_raw = derive_key("password1", Some(&raw), FAST, &salt).unwrap();
        let from_silk = derive_key("password1", Some(&silk), FAST, &salt).unwrap();
        assert_eq!(&from_raw[..], &from_silk[..]);
    }

    #[test]
    fn a_damaged_login_part_is_ignored_and_the_secret_survives() {
        let mut kf = KeyFile::generate().unwrap();
        let secret = *kf.secret();
        kf.set_login(Some(login()));
        let mut bytes = kf.to_bytes();

        bytes.truncate(bytes.len() - 5); // cut inside the JSON
        let back = KeyFile::parse(&bytes).unwrap();
        assert!(back.login().is_none());
        assert_eq!(back.secret(), &secret);

        let mut huge = kf.to_bytes();
        huge[HEAD_LEN..HEAD_LEN + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(KeyFile::parse(&huge).unwrap().login().is_none());

        // A short file that only looks like the start of one is a raw file.
        assert!(KeyFile::parse(&kf.to_bytes()[..HEAD_LEN - 1]).is_none());
    }

    #[test]
    fn the_debug_output_hides_the_token() {
        let shown = format!("{:?}", login());
        assert!(shown.contains("me@example.com"));
        assert!(!shown.contains("r1"));
    }
}
