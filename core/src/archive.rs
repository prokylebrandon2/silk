//! The archive layer: what turns the entries into the encrypted vault file stored next to the key slot.
//!
//! The archive is Kiln's `.skln` (the `kiln-skln` crate; the format is in Kiln's `docs/FORMAT.md`),
//! connected by [`crate::skln`]. Everything above this layer talks to [`Archiver`] only.
//!
//! What the flow needs from an archiver:
//! - **A raw 32-byte key.** Silk runs Argon2id itself and hands over the VEK. A password-based
//!   envelope (Kiln's scrypt lock) is not what is wanted here.
//! - **Bytes in, bytes out.** No temp files, no paths: the vault is a few hundred KB and lives in memory.
//! - **An authenticated revision counter** readable from the plain header, so a replayed old file can be noticed.
//! - **A small, lean build:** no CLI or multi-codec dependencies pulled into the Android library.
use crate::error::Error;

/// One named blob inside an archive. Wiped on drop.
pub use kiln_skln::bundle::Member;

/// A decrypted archive.
#[derive(Debug)]
pub struct Opened {
    /// Increases by one on every save. Compare it with the last value seen to catch rollbacks.
    pub revision: u64,
    pub members: Vec<Member>,
}

impl Opened {
    pub fn get(&self, name: &str) -> Option<&Member> {
        self.members.iter().find(|m| m.name == name)
    }
}

pub trait Archiver {
    /// Name of the stored object, for example `vault.skln`.
    fn file_name(&self) -> &'static str;
    /// Archives `members` and encrypts them with the VEK. Every call uses a fresh salt.
    fn seal(&self, vek: &[u8; 32], revision: u64, members: &[Member]) -> Result<Vec<u8>, Error>;
    /// Decrypts and unpacks. A wrong key, a changed header and a changed body all fail with `Corrupt`.
    fn open(&self, vek: &[u8; 32], file: &[u8]) -> Result<Opened, Error>;
    /// The revision from the plain header, without the key.
    fn revision(&self, file: &[u8]) -> Result<u64, Error>;
}

/// The archiver in use.
pub type Current = crate::skln::Skln;

pub fn current() -> Current {
    Current::default()
}
