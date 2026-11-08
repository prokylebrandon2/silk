//! The unlock and save flow from the architecture diagram, over the cloud copy of the vault.
//!
//! ```text
//! master password ──Argon2id──> key ──unwraps──> VEK ──archiver──> vault file (entries)
//!                                      (key slot)
//! first time:  random VEK -> wrap with the key -> store the key slot, then the vault file
//! afterwards:  fetch key slot -> unwrap VEK -> fetch vault file -> the archiver decrypts it
//! ```
//!
//! The archiver is Kiln's `.skln` (see [`crate::archive`]). [`CloudVault`] holds
//! the unlocked state (VEK + entries, both wiped on drop). The pure functions work on byte
//! buffers; `unlock_remote` / `save_remote` add the cloud round trips through a [`RemoteStore`].
use crate::archive::{self, Archiver, Member};
use crate::error::Error;
use crate::keyslot::KeySlot;
use crate::remote::{Object, RemoteStore};
use crate::vault::{Entry, Kdf, Vault};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// The archive member that holds the entries.
const VAULT_MEMBER: &str = "vault.json";

#[derive(Deserialize)]
struct Doc {
    entries: Vec<Entry>,
}

#[derive(Serialize)]
struct DocRef<'a> {
    entries: &'a [Entry],
}

/// Both cloud objects, as bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    pub keyslot: Vec<u8>,
    pub vault_file: Vec<u8>,
}

/// Which branch of the diagram's "subsequent unlock?" decision ran.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    /// Nothing in the cloud yet: a random VEK was created and stored.
    FirstTimeSetup,
    /// The key slot existed: the VEK was retrieved and decrypted.
    Subsequent,
}

pub struct CloudVault {
    slot: KeySlot,
    /// The key slot changed since it was last stored.
    slot_dirty: bool,
    vek: Zeroizing<[u8; 32]>,
    revision: u64,
    pub entries: Vec<Entry>,
}

impl Drop for CloudVault {
    fn drop(&mut self) {
        for e in self.entries.iter_mut() {
            e.zeroize();
        }
    }
}

impl CloudVault {
    /// First-time setup: a new random VEK wrapped under the password (and key file), empty entries.
    pub fn setup(password: &str, key_file: Option<&[u8]>, kdf: Kdf) -> Result<CloudVault, Error> {
        let (slot, vek) = KeySlot::create(password, key_file, kdf)?;
        Ok(CloudVault {
            slot,
            slot_dirty: true,
            vek,
            revision: 0,
            entries: Vec::new(),
        })
    }

    /// Subsequent unlock from bytes: Argon2id -> unwrap VEK -> the archiver decrypts the vault file.
    /// `vault_file` is `None` only for a setup that was interrupted before the vault file was stored.
    pub fn unlock(
        keyslot: &[u8],
        vault_file: Option<&[u8]>,
        password: &str,
        key_file: Option<&[u8]>,
    ) -> Result<CloudVault, Error> {
        let slot = KeySlot::from_bytes(keyslot)?;
        let vek = slot.unwrap(password, key_file)?;
        CloudVault::assemble(slot, vek, vault_file)
    }

    /// Unlock with a VEK that is already known (biometric quick unlock): no Argon2id.
    pub fn unlock_with_vek(
        keyslot: &[u8],
        vault_file: Option<&[u8]>,
        vek: &[u8; 32],
    ) -> Result<CloudVault, Error> {
        let slot = KeySlot::from_bytes(keyslot)?;
        // With no vault file there is nothing to check the VEK against, and a wrong VEK would later
        // seal a vault nobody can open. Only the password path may start from an empty vault.
        let file = vault_file.ok_or(Error::Corrupt)?;
        CloudVault::assemble(slot, Zeroizing::new(*vek), Some(file))
    }

    fn assemble(
        slot: KeySlot,
        vek: Zeroizing<[u8; 32]>,
        vault_file: Option<&[u8]>,
    ) -> Result<CloudVault, Error> {
        let (revision, entries) = match vault_file {
            Some(file) => {
                let opened = archive::current().open(&vek, file)?;
                let member = opened.get(VAULT_MEMBER).ok_or(Error::Corrupt)?;
                let doc: Doc = serde_json::from_slice(&member.data).map_err(|_| Error::Corrupt)?;
                (opened.revision, doc.entries)
            }
            None => (0, Vec::new()),
        };
        Ok(CloudVault {
            slot,
            slot_dirty: false,
            vek,
            revision,
            entries,
        })
    }

    /// Imports a legacy `.pvlt` vault: same password and key file, new VEK + key slot + entries.
    pub fn migrate_legacy(
        pvlt: &[u8],
        password: &str,
        key_file: Option<&[u8]>,
        kdf: Kdf,
    ) -> Result<CloudVault, Error> {
        let old = Vault::open(pvlt, password, key_file)?;
        let mut silk = CloudVault::setup(password, key_file, kdf)?;
        silk.entries = old.entries.clone();
        Ok(silk)
    }

    /// Encrypts the current entries into a fresh vault file (revision + 1) and returns both objects.
    pub fn seal(&mut self) -> Result<Bundle, Error> {
        let next = self.revision.checked_add(1).ok_or(Error::Corrupt)?;
        let body = serde_json::to_vec(&DocRef {
            entries: &self.entries,
        })
        .map_err(|_| Error::Corrupt)?;
        let member = Member::new(VAULT_MEMBER, body);
        let vault_file = archive::current().seal(&self.vek, next, std::slice::from_ref(&member))?;
        self.revision = next;
        Ok(Bundle {
            keyslot: self.slot.to_bytes(),
            vault_file,
        })
    }

    /// Changes the master password and/or key file. Only the small key slot is re-wrapped: the VEK
    /// and the vault file stay as they are. (The VEK is not rotated, so this does not revoke an old
    /// password for copies of the old key slot someone already holds.)
    #[cfg(test)]
    pub fn change_credentials(
        &mut self,
        new_password: &str,
        new_key_file: Option<&[u8]>,
        kdf: Kdf,
    ) -> Result<(), Error> {
        self.slot = KeySlot::wrap(&self.vek, new_password, new_key_file, kdf)?;
        self.slot_dirty = true;
        Ok(())
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

    /// A copy of the VEK for wrapping with the biometric key. Treat it like the master password.
    pub fn export_vek(&self) -> Zeroizing<[u8; 32]> {
        self.vek.clone()
    }

    /// The revision of the last vault file read or sealed.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn uses_key_file(&self) -> bool {
        self.slot.uses_key_file()
    }

    /// The whole diagram in one call. Reads the key slot from the cloud; if there is none, creates
    /// the VEK and stores everything (first-time setup), otherwise unwraps it and decrypts the vault file.
    pub fn unlock_remote(
        store: &dyn RemoteStore,
        password: &str,
        key_file: Option<&[u8]>,
        kdf: Kdf,
    ) -> Result<(CloudVault, Flow), Error> {
        match store.get(Object::KeySlot)? {
            None => {
                // A vault file with no key slot can't be decrypted by anyone. Don't build a new vault over it.
                if store.get(Object::Archive)?.is_some() {
                    return Err(Error::Corrupt);
                }
                let mut silk = CloudVault::setup(password, key_file, kdf)?;
                silk.save_remote(store)?;
                Ok((silk, Flow::FirstTimeSetup))
            }
            Some(slot_bytes) => {
                let vault_file = store.get(Object::Archive)?;
                let silk =
                    CloudVault::unlock(&slot_bytes, vault_file.as_deref(), password, key_file)?;
                Ok((silk, Flow::Subsequent))
            }
        }
    }

    /// Stores the key slot (only if it changed), then the new vault file. The key slot goes first so a
    /// half-finished first-time setup leaves a slot without a vault file, which `unlock` accepts, and
    /// never a vault file nobody can decrypt.
    pub fn save_remote(&mut self, store: &dyn RemoteStore) -> Result<(), Error> {
        let bundle = self.seal()?;
        if self.slot_dirty {
            store.put(Object::KeySlot, &bundle.keyslot)?;
            self.slot_dirty = false;
        }
        store.put(Object::Archive, &bundle.vault_file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::MemoryStore;

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
            ..Entry::default()
        }
    }

    #[test]
    fn seal_then_unlock_round_trip() {
        let kf = [3u8; 64];
        let mut s = CloudVault::setup("correct horse", Some(&kf), FAST).unwrap();
        s.upsert(entry("1", "GitHub"));
        let b = s.seal().unwrap();
        assert_eq!(s.revision(), 1);

        let back = CloudVault::unlock(&b.keyslot, Some(&b.vault_file), "correct horse", Some(&kf))
            .unwrap();
        assert_eq!(back.entries.len(), 1);
        assert_eq!(back.entries[0].title, "GitHub");
        assert_eq!(back.revision(), 1);
        assert!(back.uses_key_file());

        assert_eq!(
            CloudVault::unlock(&b.keyslot, Some(&b.vault_file), "wrong", Some(&kf)).err(),
            Some(Error::WrongCredentials)
        );
        assert_eq!(
            CloudVault::unlock(&b.keyslot, Some(&b.vault_file), "correct horse", None).err(),
            Some(Error::KeyFileRequired)
        );
    }

    #[test]
    fn revision_goes_up_on_every_save() {
        let mut s = CloudVault::setup("password1", None, FAST).unwrap();
        s.seal().unwrap();
        s.upsert(entry("1", "A"));
        let b = s.seal().unwrap();
        assert_eq!(s.revision(), 2);
        assert_eq!(archive::current().revision(&b.vault_file).unwrap(), 2);
    }

    #[test]
    fn remote_first_time_then_subsequent() {
        let store = MemoryStore::new();
        let (mut first, flow) = CloudVault::unlock_remote(&store, "password1", None, FAST).unwrap();
        assert_eq!(flow, Flow::FirstTimeSetup);
        first.upsert(entry("1", "Bank"));
        first.save_remote(&store).unwrap();

        let (again, flow) = CloudVault::unlock_remote(&store, "password1", None, FAST).unwrap();
        assert_eq!(flow, Flow::Subsequent);
        assert_eq!(again.entries.len(), 1);
        assert_eq!(again.entries[0].title, "Bank");

        assert_eq!(
            CloudVault::unlock_remote(&store, "nope", None, FAST).err(),
            Some(Error::WrongCredentials)
        );
    }

    #[test]
    fn interrupted_setup_is_recoverable_but_an_orphan_archive_is_refused() {
        // Key slot stored, vault file not: unlock gives an empty vault.
        let store = MemoryStore::new();
        let s = CloudVault::setup("password1", None, FAST).unwrap();
        store.put(Object::KeySlot, &s.slot.to_bytes()).unwrap();
        let (again, flow) = CloudVault::unlock_remote(&store, "password1", None, FAST).unwrap();
        assert_eq!(flow, Flow::Subsequent);
        assert!(again.entries.is_empty());

        // vault file without a key slot: never overwrite.
        let orphan = MemoryStore::new();
        orphan.put(Object::Archive, &[1, 2, 3]).unwrap();
        assert_eq!(
            CloudVault::unlock_remote(&orphan, "password1", None, FAST).err(),
            Some(Error::Corrupt)
        );
    }

    #[test]
    fn changing_the_password_only_touches_the_key_slot() {
        let mut s = CloudVault::setup("old password", None, FAST).unwrap();
        s.upsert(entry("1", "Mail"));
        let before = s.seal().unwrap();
        s.change_credentials("new password", None, FAST).unwrap();
        let after = s.seal().unwrap();
        assert_ne!(before.keyslot, after.keyslot);

        // The *old* vault file still opens with the new password, because the VEK didn't change.
        let reopened = CloudVault::unlock(
            &after.keyslot,
            Some(&before.vault_file),
            "new password",
            None,
        )
        .unwrap();
        assert_eq!(reopened.entries[0].title, "Mail");
        assert_eq!(
            CloudVault::unlock(
                &after.keyslot,
                Some(&after.vault_file),
                "old password",
                None
            )
            .err(),
            Some(Error::WrongCredentials)
        );
    }

    #[test]
    fn biometric_style_unlock_skips_argon2() {
        let mut s = CloudVault::setup("password1", None, FAST).unwrap();
        s.upsert(entry("1", "Mail"));
        let b = s.seal().unwrap();
        let vek = s.export_vek();
        let back = CloudVault::unlock_with_vek(&b.keyslot, Some(&b.vault_file), &vek).unwrap();
        assert_eq!(back.entries.len(), 1);
        assert_eq!(
            CloudVault::unlock_with_vek(&b.keyslot, Some(&b.vault_file), &[0u8; 32]).err(),
            Some(Error::Corrupt)
        );
    }

    #[test]
    fn legacy_pvlt_vaults_migrate() {
        let mut old = Vault::create("password1", None, FAST).unwrap();
        old.upsert(entry("1", "Old login"));
        let bytes = old.seal().unwrap();

        let mut silk = CloudVault::migrate_legacy(&bytes, "password1", None, FAST).unwrap();
        let b = silk.seal().unwrap();
        let back = CloudVault::unlock(&b.keyslot, Some(&b.vault_file), "password1", None).unwrap();
        assert_eq!(back.entries[0].title, "Old login");
        assert_eq!(
            CloudVault::migrate_legacy(&bytes, "wrong", None, FAST).err(),
            Some(Error::WrongCredentials)
        );
    }
}
