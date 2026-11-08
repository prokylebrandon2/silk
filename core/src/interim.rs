//! The stand-in archive that came before Kiln's `.skln`, kept as a **read-only source**. This is
//! not the `.skln` format.
//!
//! The cloud flow was built on this while `.skln` did not exist yet, so real vaults were written in it
//! (file `vault.interim`, magic `SKIM`, deliberately not Kiln's). Silk now writes `.skln` (see
//! [`crate::skln`]) but must keep opening these: [`crate::skln::Skln`] reads them, and
//! `session::unlock` rewrites one as `.skln` the first time it is opened. Only the tests still write it.
//!
//! ```text
//! "SKIM" | version u8 | flags u8 | revision u64 BE | nonce[12] | AES-256-GCM(archive) + tag[16]
//! archive: count u32 BE | { name_len u16 BE | name (UTF-8) | data_len u32 BE | data }*
//! ```
//!
//! The 14-byte header is bound in as associated data. Every length is checked against what is left
//! in the buffer, so a crafted file can't make the reader allocate or read past its input.
use crate::archive::{Member, Opened};
use crate::error::Error;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use std::collections::HashSet;
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"SKIM";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 14;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

pub const MAX_MEMBERS: usize = 1024;
pub const MAX_NAME_LEN: usize = 255;
#[cfg(test)]
pub const MAX_ARCHIVE_LEN: usize = 64 * 1024 * 1024;

/// Member names are labels, not paths: no separators, no `.`/`..`, no control characters.
fn check_name(name: &str) -> Result<(), Error> {
    let ok = !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name != "."
        && name != ".."
        && !name
            .chars()
            .any(|c| c == '/' || c == '\\' || c.is_control());
    if ok {
        Ok(())
    } else {
        Err(Error::Corrupt)
    }
}

/// Packs members into the archive layout. The buffer is allocated once at its final size, so no
/// stale copies are left behind by reallocation, and it is wiped on drop.
#[cfg(test)]
pub fn pack(members: &[Member]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if members.len() > MAX_MEMBERS {
        return Err(Error::Corrupt);
    }
    let mut seen = HashSet::new();
    let mut total: usize = 4;
    for m in members {
        check_name(&m.name)?;
        if !seen.insert(m.name.as_str()) {
            return Err(Error::Corrupt);
        }
        if u32::try_from(m.data.len()).is_err() {
            return Err(Error::Corrupt);
        }
        total = total.saturating_add(2 + m.name.len() + 4 + m.data.len());
    }
    if total > MAX_ARCHIVE_LEN {
        return Err(Error::Corrupt);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(total));
    out.extend_from_slice(&(members.len() as u32).to_be_bytes());
    for m in members {
        out.extend_from_slice(&(m.name.len() as u16).to_be_bytes());
        out.extend_from_slice(m.name.as_bytes());
        out.extend_from_slice(&(m.data.len() as u32).to_be_bytes());
        out.extend_from_slice(&m.data);
    }
    Ok(out)
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.buf.len())
            .ok_or(Error::Corrupt)?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u16(&mut self) -> Result<u16, Error> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
}

/// Reads the archive layout back into members. Rejects truncation, trailing bytes, duplicate or
/// unsafe names.
pub fn unpack(bytes: &[u8]) -> Result<Vec<Member>, Error> {
    let mut r = Reader { buf: bytes, pos: 0 };
    let count = r.u32()? as usize;
    if count > MAX_MEMBERS {
        return Err(Error::Corrupt);
    }
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let name_len = r.u16()? as usize;
        let name = std::str::from_utf8(r.take(name_len)?).map_err(|_| Error::Corrupt)?;
        check_name(name)?;
        if !seen.insert(name.to_owned()) {
            return Err(Error::Corrupt);
        }
        let data_len = r.u32()? as usize;
        let data = r.take(data_len)?;
        out.push(Member {
            name: name.to_owned(),
            data: data.to_vec(),
        });
    }
    if r.pos != bytes.len() {
        return Err(Error::Corrupt);
    }
    Ok(out)
}

/// Whether `file` starts with the stand-in's magic, which decides how it is read.
pub fn is_interim(file: &[u8]) -> bool {
    file.starts_with(MAGIC)
}

/// Checks that `file` looks like a stand-in vault file without needing the key.
pub fn validate(file: &[u8]) -> Result<(), Error> {
    if file.len() < HEADER_LEN + NONCE_LEN + TAG_LEN || &file[0..4] != MAGIC || file[4] != VERSION {
        return Err(Error::NotAVault);
    }
    Ok(())
}

/// The revision stored in the (plain) header, without decrypting anything.
pub fn revision(file: &[u8]) -> Result<u64, Error> {
    validate(file)?;
    Ok(u64::from_be_bytes(
        file[6..14].try_into().map_err(|_| Error::Corrupt)?,
    ))
}

/// Archives `members` and encrypts them with the VEK under a fresh random nonce.
#[cfg(test)]
pub fn seal(vek: &[u8; 32], revision: u64, members: &[Member]) -> Result<Vec<u8>, Error> {
    let archive = pack(members)?;
    let mut header = [0u8; HEADER_LEN];
    header[0..4].copy_from_slice(MAGIC);
    header[4] = VERSION;
    header[6..14].copy_from_slice(&revision.to_be_bytes());
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| Error::Random)?;
    let cipher = Aes256Gcm::new_from_slice(&vek[..]).map_err(|_| Error::Crypto)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &archive[..],
                aad: &header[..],
            },
        )
        .map_err(|_| Error::Crypto)?;
    let mut out = Vec::with_capacity(HEADER_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypts and unpacks a stand-in vault file. A wrong VEK, a changed header and a changed body all fail the
/// same way (`Corrupt`): the VEK comes out of the key slot, so a bad password never reaches here.
pub fn open(vek: &[u8; 32], file: &[u8]) -> Result<Opened, Error> {
    validate(file)?;
    let revision = revision(file)?;
    let (aad, rest) = file.split_at(HEADER_LEN);
    let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new_from_slice(&vek[..]).map_err(|_| Error::Crypto)?;
    let plain = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Corrupt)?;
    let plain = Zeroizing::new(plain);
    let members = unpack(&plain)?;
    Ok(Opened { revision, members })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [9u8; 32];

    fn sample() -> Vec<Member> {
        vec![
            Member::new("vault.json", b"{\"entries\":[]}".to_vec()),
            Member::new("readme.txt", b"hello".to_vec()),
        ]
    }

    #[test]
    fn seal_and_open_round_trip() {
        let f = seal(&KEY, 7, &sample()).unwrap();
        assert_eq!(revision(&f).unwrap(), 7);
        let back = open(&KEY, &f).unwrap();
        assert_eq!(back.revision, 7);
        assert_eq!(back.members, sample());
        assert_eq!(back.get("readme.txt").unwrap().data, b"hello");
        assert!(back.get("missing").is_none());
    }

    #[test]
    fn every_seal_uses_a_fresh_nonce() {
        assert_ne!(
            seal(&KEY, 1, &sample()).unwrap(),
            seal(&KEY, 1, &sample()).unwrap()
        );
    }

    #[test]
    fn wrong_key_and_tampering_are_rejected() {
        let f = seal(&KEY, 3, &sample()).unwrap();
        assert_eq!(open(&[1u8; 32], &f).err(), Some(Error::Corrupt));

        let mut body = f.clone();
        let last = body.len() - 1;
        body[last] ^= 1;
        assert_eq!(open(&KEY, &body).err(), Some(Error::Corrupt));

        // The revision is authenticated: a server can't quietly rewrite it.
        let mut hdr = f.clone();
        hdr[13] ^= 1;
        assert_eq!(open(&KEY, &hdr).err(), Some(Error::Corrupt));
    }

    #[test]
    fn rejects_files_that_are_not_archives() {
        assert_eq!(validate(b"nope").err(), Some(Error::NotAVault));
        assert_eq!(open(&KEY, &[0u8; 64]).err(), Some(Error::NotAVault));
    }

    #[test]
    fn unpack_rejects_truncated_and_trailing_data() {
        let packed = pack(&sample()).unwrap().to_vec();
        assert_eq!(unpack(&packed).unwrap(), sample());
        assert_eq!(
            unpack(&packed[..packed.len() - 1]).err(),
            Some(Error::Corrupt)
        );
        assert_eq!(unpack(&packed[..10]).err(), Some(Error::Corrupt));
        let mut extra = packed.clone();
        extra.push(0);
        assert_eq!(unpack(&extra).err(), Some(Error::Corrupt));
        // A huge member count must fail cleanly, not allocate.
        assert_eq!(unpack(&u32::MAX.to_be_bytes()).err(), Some(Error::Corrupt));
    }

    #[test]
    fn pack_rejects_duplicate_and_unsafe_names() {
        let dup = [Member::new("a", vec![]), Member::new("a", vec![])];
        assert_eq!(pack(&dup).err(), Some(Error::Corrupt));
        for bad in ["", "..", ".", "a/b", "a\\b", "nul\0"] {
            assert_eq!(
                pack(&[Member::new(bad, vec![])]).err(),
                Some(Error::Corrupt),
                "{bad:?}"
            );
        }
    }
}
