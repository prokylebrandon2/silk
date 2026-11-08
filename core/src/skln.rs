//! Kiln's `.skln` as Silk's vault file (`vault.skln`): the [`Archiver`] in use.
//!
//! The `kiln-skln` crate does the sealing: a bundle whose one member is `vault.json`, cut into
//! ChaCha20-Poly1305 records under a key derived from the VEK and a fresh salt, with the revision in
//! the plain header (authenticated, readable without the key). This file only connects it to the
//! trait and turns its errors into Silk's.
use crate::archive::{Archiver, Member, Opened};
use crate::error::Error;
use kiln_skln::bundle;

#[derive(Clone, Copy, Debug, Default)]
pub struct Skln;

fn convert(e: kiln_skln::Error) -> Error {
    use kiln_skln::Error as E;
    match e {
        E::NotSkln | E::Unsupported => Error::NotAVault,
        E::Corrupt | E::Limit => Error::Corrupt,
        E::Random => Error::Random,
        E::Internal => Error::Crypto,
    }
}

impl Archiver for Skln {
    fn file_name(&self) -> &'static str {
        "vault.skln"
    }

    fn seal(&self, vek: &[u8; 32], revision: u64, members: &[Member]) -> Result<Vec<u8>, Error> {
        bundle::seal_bundle(vek, revision, members).map_err(convert)
    }

    fn open(&self, vek: &[u8; 32], file: &[u8]) -> Result<Opened, Error> {
        let opened = bundle::open_bundle(vek, file).map_err(convert)?;
        Ok(Opened {
            revision: opened.revision,
            members: opened.members,
        })
    }

    fn revision(&self, file: &[u8]) -> Result<u64, Error> {
        kiln_skln::revision(file).map_err(convert)
    }
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
        let f = Skln.seal(&KEY, 7, &sample()).unwrap();
        assert!(f.starts_with(&kiln_skln::MAGIC));
        assert_eq!(Skln.revision(&f).unwrap(), 7);
        let back = Skln.open(&KEY, &f).unwrap();
        assert_eq!(back.revision, 7);
        assert_eq!(back.members, sample());
        assert_eq!(back.get("readme.txt").unwrap().data, b"hello");
        assert!(back.get("missing").is_none());
    }

    #[test]
    fn every_seal_is_different() {
        assert_ne!(
            Skln.seal(&KEY, 1, &sample()).unwrap(),
            Skln.seal(&KEY, 1, &sample()).unwrap()
        );
    }

    #[test]
    fn wrong_key_and_tampering_are_rejected() {
        let f = Skln.seal(&KEY, 3, &sample()).unwrap();
        assert_eq!(Skln.open(&[1u8; 32], &f).err(), Some(Error::Corrupt));

        let mut body = f.clone();
        let last = body.len() - 1;
        body[last] ^= 1;
        assert_eq!(Skln.open(&KEY, &body).err(), Some(Error::Corrupt));

        // The revision is authenticated: a server can't quietly rewrite it.
        let mut hdr = f.clone();
        hdr[12] ^= 1;
        assert_eq!(Skln.open(&KEY, &hdr).err(), Some(Error::Corrupt));
    }

    #[test]
    fn other_files_are_not_vault_files() {
        assert_eq!(Skln.open(&KEY, b"nope").err(), Some(Error::NotAVault));
        assert_eq!(Skln.revision(b"nope").err(), Some(Error::NotAVault));
        assert_eq!(Skln.open(&KEY, &[0u8; 64]).err(), Some(Error::NotAVault));
    }

    #[test]
    fn a_skln_that_is_not_a_bundle_is_refused() {
        let f = kiln_skln::seal(&KEY, kiln_skln::Kind::Archive, 1, b"x").unwrap();
        assert_eq!(Skln.open(&KEY, &f).err(), Some(Error::NotAVault));
    }
}
