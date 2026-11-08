//! The backup file: the key slot and the vault file in one piece, so a backup is a single file
//! that can be restored on its own.
//!
//! ```text
//! "SKBK" | version u8 | key slot (91 bytes) | vault file (the rest)
//! ```
//!
//! Both parts are already encrypted; the bundle adds nothing secret. Old backups from before the
//! key slot existed are plain `.pvlt` files (see `vault`) and are still accepted by
//! `Session::import`, which converts them on the next unlock.
use crate::archive::{self, Archiver};
use crate::error::Error;
use crate::keyslot::{KeySlot, KEYSLOT_LEN};

const MAGIC: &[u8; 4] = b"SKBK";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 5;

/// Joins a key slot and a vault file. Both are checked first, so a bad pair can't be written.
pub fn pack(keyslot: &[u8], vault_file: &[u8]) -> Result<Vec<u8>, Error> {
    KeySlot::from_bytes(keyslot)?;
    archive::current().revision(vault_file)?;
    let mut out = Vec::with_capacity(HEADER_LEN + keyslot.len() + vault_file.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(keyslot);
    out.extend_from_slice(vault_file);
    Ok(out)
}

/// Splits a bundle into `(key slot, vault file)` and checks that both parts look right.
/// The password isn't needed; a wrong pairing shows up when the backup is unlocked.
pub fn unpack(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    if bytes.len() < HEADER_LEN + KEYSLOT_LEN || &bytes[0..4] != MAGIC || bytes[4] != VERSION {
        return Err(Error::NotAVault);
    }
    let (slot, file) = bytes[HEADER_LEN..].split_at(KEYSLOT_LEN);
    KeySlot::from_bytes(slot)?;
    archive::current().revision(file)?;
    Ok((slot.to_vec(), file.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::Member;
    use crate::vault::Kdf;

    const FAST: Kdf = Kdf {
        t: 1,
        mem_kib: 64,
        p: 1,
    };

    fn parts() -> (Vec<u8>, Vec<u8>) {
        let (slot, vek) = KeySlot::create("password1", None, FAST).unwrap();
        let file = archive::current()
            .seal(
                &vek,
                1,
                &[Member::new("vault.json", b"{\"entries\":[]}".to_vec())],
            )
            .unwrap();
        (slot.to_bytes(), file)
    }

    #[test]
    fn pack_then_unpack_gives_the_same_two_parts() {
        let (slot, file) = parts();
        let bundle = pack(&slot, &file).unwrap();
        assert_eq!(unpack(&bundle).unwrap(), (slot, file));
    }

    #[test]
    fn other_files_and_damaged_bundles_are_rejected() {
        let (slot, file) = parts();
        assert_eq!(unpack(b"hello").err(), Some(Error::NotAVault));
        assert_eq!(pack(b"short", &file).err(), Some(Error::NotAVault));
        assert_eq!(
            pack(&slot, b"not a vault file at all").err(),
            Some(Error::NotAVault)
        );

        let bundle = pack(&slot, &file).unwrap();
        assert_eq!(
            unpack(&bundle[..HEADER_LEN + 10]).err(),
            Some(Error::NotAVault)
        );
        let mut wrong_version = bundle.clone();
        wrong_version[4] = 9;
        assert_eq!(unpack(&wrong_version).err(), Some(Error::NotAVault));
        // A vault file that doesn't start like one is refused even with a good key slot in front.
        let mut bad_file = bundle.clone();
        bad_file[HEADER_LEN + KEYSLOT_LEN] ^= 0xff;
        assert_eq!(unpack(&bad_file).err(), Some(Error::NotAVault));
    }
}
