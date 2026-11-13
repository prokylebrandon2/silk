//! The unlocked state the app holds, on top of the cloud architecture (`cloud`, `keyslot`, `archive`).
//!
//! Key derivation is slow, so the free functions [`unlock`] and [`unlock_with_vek`] do the heavy work
//! *outside* the [`Session`] (autofill runs on other threads and must not wait behind Argon2id); the
//! caller then hands the opened vault to [`Session::install`]. Every change is saved straight to the
//! local copy (`local::DirStore`: key slot + vault file in the app's private folder).
use crate::backup;
use crate::cloud::{CloudVault, Flow};
use crate::entry::Entry;
use crate::error::Error;
use crate::kdf::Kdf;
use crate::local::DirStore;
use crate::remote::{Object, RemoteStore};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

/// Opens or creates the vault in `store` with the master password. Slow (Argon2id).
/// `kdf` is used only when a key slot is created (first-time setup).
pub fn unlock(
    store: &DirStore,
    password: &str,
    key_file: Option<&[u8]>,
    kdf: Kdf,
) -> Result<CloudVault, Error> {
    let (vault, flow) = CloudVault::unlock_remote(store, password, key_file, kdf)?;
    if flow == Flow::Subsequent {
        store.check_revision(vault.revision())?;
    }
    Ok(vault)
}

/// Biometric quick unlock: the VEK comes from the Keystore, so there is no Argon2id.
pub fn unlock_with_vek(store: &DirStore, vek: &[u8; 32]) -> Result<CloudVault, Error> {
    let slot = store.get(Object::KeySlot)?.ok_or(Error::NotAVault)?;
    let file = store.get(Object::Archive)?;
    let vault = CloudVault::unlock_with_vek(&slot, file.as_deref(), vek)?;
    store.check_revision(vault.revision())?;
    Ok(vault)
}

/// Holds the unlocked vault in memory and the location of the local copy. Locks itself after
/// `idle` without activity.
pub struct Session {
    store: Option<DirStore>,
    vault: Option<CloudVault>,
    last_use: Option<Instant>,
    idle: Duration,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    pub const fn new() -> Self {
        Session {
            store: None,
            vault: None,
            last_use: None,
            idle: Duration::from_secs(300),
        }
    }

    pub fn set_dir(&mut self, dir: PathBuf) {
        self.store = Some(DirStore::new(dir));
    }

    #[cfg(test)]
    pub fn set_idle_limit(&mut self, idle: Duration) {
        self.idle = idle;
    }

    /// The local store (a cheap copy of the folder location), for work done outside the session lock.
    pub fn store(&self) -> Result<DirStore, Error> {
        self.store
            .clone()
            .ok_or_else(|| Error::Io("no data directory".into()))
    }

    /// True when there is a vault to unlock.
    pub fn exists(&self) -> bool {
        self.store
            .as_ref()
            .map(|s| s.has(Object::KeySlot))
            .unwrap_or(false)
    }

    pub fn touch(&mut self) {
        self.last_use = Some(Instant::now());
    }

    pub fn check_idle(&mut self) {
        if self.vault.is_some() {
            if let Some(t) = self.last_use {
                if t.elapsed() > self.idle {
                    self.lock();
                }
            }
        }
    }

    pub fn is_unlocked(&mut self) -> bool {
        self.check_idle();
        self.vault.is_some()
    }

    /// Drops the vault, which wipes its VEK and entries.
    pub fn lock(&mut self) {
        self.vault = None;
    }

    /// Takes over an opened or freshly created vault.
    pub fn install(&mut self, vault: CloudVault) -> Result<(), Error> {
        if let Some(s) = &self.store {
            s.record_revision(vault.revision())?;
        }
        self.vault = Some(vault);
        self.touch();
        Ok(())
    }

    /// The VEK for wrapping by the biometric key, or `Locked`. Treat it like the master password.
    pub fn export_vek(&mut self) -> Result<Zeroizing<[u8; 32]>, Error> {
        self.check_idle();
        self.vault
            .as_ref()
            .map(|v| v.export_vek())
            .ok_or(Error::Locked)
    }

    /// The entries, or `None` while locked.
    pub fn entries(&mut self) -> Option<&[Entry]> {
        self.check_idle();
        self.vault.as_ref().map(|v| v.entries.as_slice())
    }

    /// Saves the current entries to the local copy and raises the rollback mark.
    fn save(&mut self) -> Result<(), Error> {
        let store = self.store()?;
        let v = self.vault.as_mut().ok_or(Error::Locked)?;
        v.save_remote(&store)?;
        store.record_revision(v.revision())
    }

    pub fn upsert(&mut self, e: Entry) -> Result<(), Error> {
        self.check_idle();
        self.vault.as_mut().ok_or(Error::Locked)?.upsert(e);
        self.save()?;
        self.touch();
        Ok(())
    }

    pub fn remove(&mut self, id: &str) -> Result<(), Error> {
        self.check_idle();
        self.vault.as_mut().ok_or(Error::Locked)?.remove(id);
        self.save()?;
        self.touch();
        Ok(())
    }

    /// Deletes a folder. The items in it stay in the vault, no longer in any folder.
    pub fn remove_folder(&mut self, id: &str) -> Result<(), Error> {
        self.check_idle();
        let v = self.vault.as_mut().ok_or(Error::Locked)?;
        for e in v.entries.iter_mut().filter(|e| e.folder == id) {
            e.folder.clear();
        }
        v.remove(id);
        self.save()?;
        self.touch();
        Ok(())
    }

    /// Adds imported logins in one save. A login already in the vault (same title, username, website
    /// and password) is skipped. Returns `(added, duplicates)`.
    pub fn merge_entries(&mut self, incoming: Vec<Entry>) -> Result<(usize, usize), Error> {
        self.check_idle();
        let (added, dups) = {
            let v = self.vault.as_mut().ok_or(Error::Locked)?;
            let (mut added, mut dups) = (0usize, 0usize);
            for mut e in incoming {
                if v.entries.iter().any(|x| same_login(x, &e)) {
                    e.zeroize();
                    dups += 1;
                } else {
                    v.upsert(e);
                    added += 1;
                }
            }
            (added, dups)
        };
        if added > 0 {
            self.save()?;
        }
        self.touch();
        Ok((added, dups))
    }

    /// The backup file: key slot and vault file as last saved, still encrypted.
    pub fn read_backup(&self) -> Result<Vec<u8>, Error> {
        let store = self.store()?;
        let slot = store.get(Object::KeySlot)?.ok_or(Error::NotAVault)?;
        let file = store.get(Object::Archive)?.ok_or(Error::NotAVault)?;
        backup::pack(&slot, &file)
    }

    /// Replaces the stored vault with a Silk backup (which stays encrypted). Restoring is the one
    /// deliberate way to go back to an older vault, so it also clears the rollback mark and the cloud link.
    pub fn import(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let store = self.store()?;
        let (slot, file) = backup::unpack(bytes)?;
        store.put(Object::Archive, &file)?;
        store.put(Object::KeySlot, &slot)?;
        store.forget_revision()?;
        // The restored vault may be older than the cloud copy. Without the link the next sync asks
        // which one to keep instead of quietly undoing the restore.
        store.unlink()?;
        self.lock();
        Ok(())
    }
}

fn same_login(a: &Entry, b: &Entry) -> bool {
    a.title.trim().eq_ignore_ascii_case(b.title.trim())
        && a.username.trim().eq_ignore_ascii_case(b.username.trim())
        && a.url.trim().eq_ignore_ascii_case(b.url.trim())
        && a.password == b.password
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::new_id;

    const FAST: Kdf = Kdf {
        t: 1,
        mem_kib: 64,
        p: 1,
    };

    fn temp_session() -> Session {
        let dir = std::env::temp_dir().join(format!("silk-test-{}", new_id()));
        let mut s = Session::new();
        s.set_dir(dir);
        s
    }

    fn entry(id: &str) -> Entry {
        Entry {
            id: id.into(),
            title: "Site".into(),
            username: "me".into(),
            password: "pw".into(),
            ..Entry::default()
        }
    }

    /// Unlocks (or creates) with the password and installs the vault.
    fn open_with(s: &mut Session, password: &str) {
        let store = s.store().unwrap();
        let vault = unlock(&store, password, None, FAST).unwrap();
        s.install(vault).unwrap();
    }

    #[test]
    fn create_save_lock_and_reopen() {
        let mut s = temp_session();
        assert!(!s.exists());
        open_with(&mut s, "password1");
        assert!(s.exists());
        s.upsert(entry("1")).unwrap();
        assert_eq!(s.entries().unwrap().len(), 1);

        s.lock();
        assert!(s.entries().is_none());
        assert_eq!(s.upsert(entry("2")).err(), Some(Error::Locked));

        open_with(&mut s, "password1");
        assert_eq!(s.entries().unwrap()[0].id, "1");
        s.remove("1").unwrap();
        assert!(s.entries().unwrap().is_empty());

        let store = s.store().unwrap();
        assert_eq!(
            unlock(&store, "wrong", None, FAST).err(),
            Some(Error::WrongCredentials)
        );
    }

    #[test]
    fn locks_itself_when_idle() {
        let mut s = temp_session();
        open_with(&mut s, "password1");
        s.set_idle_limit(Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(15));
        assert!(!s.is_unlocked());
    }

    #[test]
    fn merge_skips_duplicates_and_saves_once() {
        let mut s = temp_session();
        open_with(&mut s, "password1");
        s.upsert(entry("1")).unwrap();
        let mut same = entry("other-id");
        same.title = "SITE".into(); // case differs only
        let mut fresh = entry("2");
        fresh.title = "Fresh".into();
        assert_eq!(s.merge_entries(vec![same, fresh]).unwrap(), (1, 1));
        assert_eq!(s.entries().unwrap().len(), 2);
        // what was merged is on disk
        s.lock();
        open_with(&mut s, "password1");
        assert_eq!(s.entries().unwrap().len(), 2);
        s.lock();
        assert_eq!(s.merge_entries(vec![entry("3")]).err(), Some(Error::Locked));
    }

    #[test]
    fn backups_round_trip_and_other_files_are_rejected() {
        let mut a = temp_session();
        open_with(&mut a, "password1");
        a.upsert(entry("1")).unwrap();
        let backup = a.read_backup().unwrap();

        let mut b = temp_session();
        assert_eq!(b.import(b"hello").err(), Some(Error::NotAVault));
        assert!(!b.exists());
        b.import(&backup).unwrap();
        assert!(b.exists());
        open_with(&mut b, "password1");
        assert_eq!(b.entries().unwrap()[0].id, "1");
    }

    #[test]
    fn an_older_vault_file_is_refused_but_a_restore_may_go_back() {
        let mut s = temp_session();
        open_with(&mut s, "password1"); // revision 1
        let backup_at_1 = s.read_backup().unwrap();
        let store = s.store().unwrap();
        let file_at_1 = store.get(Object::Archive).unwrap().unwrap();
        s.upsert(entry("1")).unwrap(); // revision 2
        s.lock();

        // Someone hands back the old vault file.
        store.put(Object::Archive, &file_at_1).unwrap();
        assert_eq!(
            unlock(&store, "password1", None, FAST).err(),
            Some(Error::Rollback)
        );

        // Restoring a backup on purpose is allowed and resets the mark.
        s.import(&backup_at_1).unwrap();
        open_with(&mut s, "password1");
        assert!(s.entries().unwrap().is_empty());
    }

    #[test]
    fn deleting_a_folder_keeps_its_items() {
        let mut s = temp_session();
        open_with(&mut s, "password1");
        s.upsert(Entry {
            id: "f".into(),
            title: "Work".into(),
            kind: "folder".into(),
            ..Entry::default()
        })
        .unwrap();
        let mut inside = entry("1");
        inside.folder = "f".into();
        s.upsert(inside).unwrap();
        s.remove_folder("f").unwrap();
        let left = s.entries().unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].id, "1");
        assert!(left[0].folder.is_empty());
    }

    #[test]
    fn biometric_unlock_uses_the_vek_and_rejects_a_wrong_one() {
        let mut s = temp_session();
        open_with(&mut s, "password1");
        s.upsert(entry("1")).unwrap();
        let vek = s.export_vek().unwrap();
        s.lock();
        assert_eq!(s.export_vek().err(), Some(Error::Locked));

        let store = s.store().unwrap();
        let vault = unlock_with_vek(&store, &vek).unwrap();
        assert_eq!(vault.entries.len(), 1);
        assert_eq!(
            unlock_with_vek(&store, &[0u8; 32]).err(),
            Some(Error::Corrupt)
        );
    }
}
