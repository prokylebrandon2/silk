//! The on-device copy of the two cloud objects, in the app's private folder.
//!
//! [`DirStore`] implements [`RemoteStore`], so the very same `CloudVault::unlock_remote` and
//! `save_remote` flow that talks to the cloud also runs against this folder. That gives offline
//! unlock for free: the cloud copy, once it exists, is synced into this folder and unlocking reads
//! from here.
//!
//! Files in the folder:
//! ```text
//! keyslot.skvk     the key slot (VEK wrapped by the Argon2id key)
//! vault.skln       the vault file (Kiln's `.skln`)
//! seen.rev         the highest vault revision this device has seen (rollback guard)
//! sync.uid         the cloud account this copy was last synced with (see `sync`)
//! ```
//! Writes go to a temporary file first and are renamed into place, so a crash leaves either the old
//! file or the new one, never half of each.
use crate::error::Error;
use crate::remote::{Object, RemoteStore};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const SEEN_FILE: &str = "seen.rev";
const LINK_FILE: &str = "sync.uid";

#[derive(Clone, Debug)]
pub struct DirStore {
    dir: PathBuf,
}

impl DirStore {
    pub fn new(dir: PathBuf) -> DirStore {
        DirStore { dir }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path(&self, object: Object) -> PathBuf {
        self.dir.join(object.file_name())
    }

    pub fn has(&self, object: Object) -> bool {
        self.path(object).is_file()
    }

    pub fn remove(&self, object: Object) -> Result<(), Error> {
        remove_if_exists(&self.path(object))
    }

    // ---- rollback guard ----
    //
    // Every vault file carries an authenticated revision that goes up on each save. The device keeps
    // the highest one it has seen; a file with a lower revision is an old copy (a server replaying
    // an old upload, or a swapped file) and is refused. Restoring a backup on purpose clears the
    // mark (`forget_revision`), because that is the one legitimate way to go back.

    /// The highest revision recorded so far, 0 if none (or if the mark can't be read).
    pub fn seen_revision(&self) -> u64 {
        fs::read_to_string(self.dir.join(SEEN_FILE))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    }

    /// `Err(Rollback)` when `revision` is lower than one already seen.
    pub fn check_revision(&self, revision: u64) -> Result<(), Error> {
        if revision < self.seen_revision() {
            Err(Error::Rollback)
        } else {
            Ok(())
        }
    }

    /// Raises the mark to `revision`; never lowers it.
    pub fn record_revision(&self, revision: u64) -> Result<(), Error> {
        if revision > self.seen_revision() {
            write_atomic(&self.dir.join(SEEN_FILE), revision.to_string().as_bytes())
        } else {
            Ok(())
        }
    }

    pub fn forget_revision(&self) -> Result<(), Error> {
        remove_if_exists(&self.dir.join(SEEN_FILE))
    }

    // ---- cloud link ----
    //
    // `sync.uid` records which cloud account this device's vault has been synced with. Until it
    // matches the signed-in account, `sync::run` refuses to copy anything over a vault that differs.

    /// The uid of the account this copy was last synced with.
    pub fn linked_uid(&self) -> Option<String> {
        fs::read_to_string(self.dir.join(LINK_FILE))
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
    }

    pub fn link(&self, uid: &str) -> Result<(), Error> {
        if self.linked_uid().as_deref() == Some(uid) {
            return Ok(());
        }
        write_atomic(&self.dir.join(LINK_FILE), uid.as_bytes())
    }

    pub fn unlink(&self) -> Result<(), Error> {
        remove_if_exists(&self.dir.join(LINK_FILE))
    }
}

impl RemoteStore for DirStore {
    fn get(&self, object: Object) -> Result<Option<Vec<u8>>, Error> {
        read_optional(&self.path(object))
    }

    fn put(&self, object: Object, data: &[u8]) -> Result<(), Error> {
        write_atomic(&self.path(object), data)
    }

    fn delete(&self, object: Object) -> Result<(), Error> {
        self.remove(object)
    }
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, Error> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn remove_if_exists(path: &Path) -> Result<(), Error> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::new_id;

    fn temp_store() -> DirStore {
        DirStore::new(std::env::temp_dir().join(format!("silk-local-{}", new_id())))
    }

    #[test]
    fn missing_objects_are_none_and_stored_ones_come_back() {
        let s = temp_store();
        assert_eq!(s.get(Object::KeySlot).unwrap(), None);
        assert!(!s.has(Object::KeySlot));
        s.put(Object::KeySlot, b"slot").unwrap();
        s.put(Object::Archive, b"vault").unwrap();
        assert_eq!(s.get(Object::KeySlot).unwrap().unwrap(), b"slot");
        assert_eq!(s.get(Object::Archive).unwrap().unwrap(), b"vault");
        // Overwriting replaces, and no temporary file is left behind.
        s.put(Object::KeySlot, b"slot2").unwrap();
        assert_eq!(s.get(Object::KeySlot).unwrap().unwrap(), b"slot2");
        assert!(!s.dir().join("keyslot.skvk.tmp").exists());
        s.remove(Object::KeySlot).unwrap();
        s.remove(Object::KeySlot).unwrap(); // removing what isn't there is fine
        assert!(!s.has(Object::KeySlot));
    }

    #[test]
    fn the_cloud_link_is_remembered_and_can_be_dropped() {
        let s = temp_store();
        assert_eq!(s.linked_uid(), None);
        s.link("uid1").unwrap();
        s.link("uid1").unwrap();
        assert_eq!(s.linked_uid().as_deref(), Some("uid1"));
        s.link("uid2").unwrap();
        assert_eq!(s.linked_uid().as_deref(), Some("uid2"));
        s.unlink().unwrap();
        s.unlink().unwrap(); // dropping what isn't there is fine
        assert_eq!(s.linked_uid(), None);
    }

    #[test]
    fn the_seen_revision_only_goes_up_and_old_files_are_refused() {
        let s = temp_store();
        assert_eq!(s.seen_revision(), 0);
        s.check_revision(0).unwrap();
        s.record_revision(5).unwrap();
        s.record_revision(3).unwrap(); // never lowered
        assert_eq!(s.seen_revision(), 5);
        s.check_revision(5).unwrap();
        s.check_revision(9).unwrap();
        assert_eq!(s.check_revision(4).err(), Some(Error::Rollback));
        s.forget_revision().unwrap();
        s.check_revision(1).unwrap();
    }
}
