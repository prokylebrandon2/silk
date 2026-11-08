//! Keeps the on-device copy (`local::DirStore`) and the cloud copy (any `RemoteStore`, Supabase
//! Storage in the app) in step. The device always unlocks from its own copy; this module moves the two
//! objects (key slot, vault file) between the two places.
//!
//! The rule is the authenticated **revision** inside the vault file: the higher one wins, and a
//! lower one is never accepted over a higher one (a download also goes through the rollback guard).
//!
//! Two things are never done silently, because either would destroy a vault:
//! - **Unrelated vaults.** The first time this device meets an account, if both sides already hold a
//!   vault and they differ, nothing is copied ([`Report::Unlinked`]). The user picks
//!   [`Mode::KeepLocal`] or [`Mode::UseCloud`]. Once a device has synced with an account (it records
//!   the account's uid, see `DirStore::link`) the revision rule is used from then on. Restoring a
//!   backup drops the link again, so an older restore is not undone by the next sync.
//! - **Two devices saving the same revision.** The files differ but neither is newer
//!   ([`Report::Conflict`]). Nothing is copied; the next save on either device gets the next
//!   revision and then wins. There is no merge (see "Known limits" in the architecture notes).
use crate::archive::{self, Archiver};
use crate::error::Error;
use crate::keyslot::KeySlot;
use crate::local::DirStore;
use crate::remote::{Object, RemoteStore};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// After a save: upload when this device is ahead, but never replace the local copy.
    Push,
    /// Both ways, by revision. May replace the local copy with a newer cloud copy.
    Sync,
    /// The user's choice after [`Report::Unlinked`]: this device's vault replaces the cloud one.
    KeepLocal,
    /// The user's choice after [`Report::Unlinked`]: the cloud vault replaces this device's.
    UseCloud,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Report {
    /// Both sides were already the same (or there was nothing to do).
    UpToDate,
    /// This device was ahead (or the cloud was empty): the cloud copy was written.
    Uploaded,
    /// The cloud was ahead: the local copy was replaced. A vault that is unlocked in memory is now stale and must be reopened.
    Downloaded,
    /// The cloud is ahead, but the mode doesn't allow replacing the local copy.
    CloudNewer,
    /// Same revision, different files: two devices saved from the same base. Nothing was changed.
    Conflict,
    /// This device and the account hold different vaults that were never linked. Nothing was changed.
    Unlinked,
}

pub fn run(
    local: &DirStore,
    cloud: &dyn RemoteStore,
    uid: &str,
    mode: Mode,
) -> Result<Report, Error> {
    let l_slot = local.get(Object::KeySlot)?;
    let l_file = local.get(Object::Archive)?;
    let c_slot = cloud.get(Object::KeySlot)?;
    let c_file = cloud.get(Object::Archive)?;

    // A vault file in the cloud without a key slot can't be opened by anyone. Never build on it.
    if c_slot.is_none() && c_file.is_some() {
        return Err(Error::Corrupt);
    }

    match mode {
        Mode::KeepLocal => {
            let slot = l_slot.ok_or(Error::NotAVault)?;
            upload(cloud, &slot, l_file.as_deref(), None)?;
            local.link(uid)?;
            return Ok(Report::Uploaded);
        }
        Mode::UseCloud => {
            let slot = c_slot.ok_or(Error::NotAVault)?;
            download(local, &slot, c_file.as_deref(), true)?;
            // An old .pvlt is given up here: the user chose the cloud vault over everything on this device.
            local.remove_legacy()?;
            local.link(uid)?;
            return Ok(Report::Downloaded);
        }
        Mode::Push | Mode::Sync => {}
    }

    let Some(l_slot) = l_slot else {
        // Nothing usable on this device yet (or only an old .pvlt that hasn't been converted).
        return match c_slot {
            None => Ok(Report::UpToDate),
            Some(_) if local.has_legacy() => Ok(Report::Unlinked),
            Some(_) if mode == Mode::Push => Ok(Report::UpToDate),
            Some(slot) => {
                download(local, &slot, c_file.as_deref(), false)?;
                local.link(uid)?;
                Ok(Report::Downloaded)
            }
        };
    };

    let Some(c_slot) = c_slot else {
        upload(cloud, &l_slot, l_file.as_deref(), None)?;
        local.link(uid)?;
        return Ok(Report::Uploaded);
    };

    let same = l_slot == c_slot && l_file == c_file;
    if local.linked_uid().as_deref() != Some(uid) {
        if same {
            local.link(uid)?;
            return Ok(Report::UpToDate);
        }
        return Ok(Report::Unlinked);
    }

    let l_rev = revision_of(l_file.as_deref())?;
    let c_rev = revision_of(c_file.as_deref())?;
    if c_rev > l_rev {
        if mode == Mode::Push {
            return Ok(Report::CloudNewer);
        }
        download(local, &c_slot, c_file.as_deref(), false)?;
        Ok(Report::Downloaded)
    } else if c_rev < l_rev {
        upload(cloud, &l_slot, l_file.as_deref(), Some(c_slot.as_slice()))?;
        Ok(Report::Uploaded)
    } else if same {
        Ok(Report::UpToDate)
    } else {
        Ok(Report::Conflict)
    }
}

fn revision_of(file: Option<&[u8]>) -> Result<u64, Error> {
    match file {
        Some(f) => archive::current().revision(f),
        None => Ok(0),
    }
}

/// Key slot first (and only if it differs), then the vault file: an interrupted upload leaves a slot
/// without a vault file, which unlock accepts as an empty vault, never a vault file nobody can open.
fn upload(
    cloud: &dyn RemoteStore,
    slot: &[u8],
    file: Option<&[u8]>,
    cloud_slot: Option<&[u8]>,
) -> Result<(), Error> {
    if cloud_slot != Some(slot) {
        cloud.put(Object::KeySlot, slot)?;
    }
    if let Some(f) = file {
        cloud.put(Object::Archive, f)?;
    }
    Ok(())
}

/// Checks both parts, then writes them like a restore does: vault file first, then the key slot.
/// `deliberate` is the user choosing the cloud vault, which is allowed to be older than what this
/// device has seen, so it clears the rollback mark; otherwise the rollback guard applies.
fn download(
    local: &DirStore,
    slot: &[u8],
    file: Option<&[u8]>,
    deliberate: bool,
) -> Result<(), Error> {
    KeySlot::from_bytes(slot)?;
    let rev = match file {
        Some(f) => Some(archive::current().revision(f)?),
        None => None,
    };
    if deliberate {
        local.forget_revision()?;
    } else if let Some(r) = rev {
        local.check_revision(r)?;
    }
    match file {
        Some(f) => local.put(Object::Archive, f)?,
        None => local.remove(Object::Archive)?,
    }
    local.put(Object::KeySlot, slot)?;
    if let Some(r) = rev {
        local.record_revision(r)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud::CloudVault;
    use crate::remote::MemoryStore;
    use crate::session::{self, Unlocked};
    use crate::vault::{new_id, Entry, Kdf};

    const FAST: Kdf = Kdf {
        t: 1,
        mem_kib: 64,
        p: 1,
    };
    const UID: &str = "uid1";

    fn temp_store() -> DirStore {
        DirStore::new(std::env::temp_dir().join(format!("silk-sync-{}", new_id())))
    }

    fn entry(id: &str, title: &str) -> Entry {
        Entry {
            id: id.into(),
            title: title.into(),
            username: "me".into(),
            password: "pw".into(),
            ..Entry::default()
        }
    }

    /// A device that has just created its own vault (revision 1).
    fn new_device(password: &str) -> (DirStore, CloudVault) {
        let store = temp_store();
        let Unlocked { vault, .. } = session::unlock(&store, password, None, FAST).unwrap();
        (store, vault)
    }

    fn change(store: &DirStore, vault: &mut CloudVault, title: &str) {
        vault.upsert(entry(title, title));
        vault.save_remote(store).unwrap();
    }

    #[test]
    fn the_first_sync_uploads_and_the_next_finds_nothing_to_do() {
        let (a, _vault) = new_device("password1");
        let cloud = MemoryStore::new();
        assert_eq!(run(&a, &cloud, UID, Mode::Sync).unwrap(), Report::Uploaded);
        assert!(cloud.get(Object::KeySlot).unwrap().is_some());
        assert!(cloud.get(Object::Archive).unwrap().is_some());
        assert_eq!(a.linked_uid().as_deref(), Some(UID));
        assert_eq!(run(&a, &cloud, UID, Mode::Sync).unwrap(), Report::UpToDate);
    }

    #[test]
    fn a_new_device_downloads_and_the_newer_side_wins_after_that() {
        let (a, _a_vault) = new_device("password1");
        let cloud = MemoryStore::new();
        run(&a, &cloud, UID, Mode::Sync).unwrap();

        // Device B has nothing: it gets the vault, opens it with the same password and adds a login.
        let b = temp_store();
        assert_eq!(run(&b, &cloud, UID, Mode::Push).unwrap(), Report::UpToDate); // a push never pulls
        assert_eq!(
            run(&b, &cloud, UID, Mode::Sync).unwrap(),
            Report::Downloaded
        );
        let Unlocked {
            vault: mut b_vault, ..
        } = session::unlock(&b, "password1", None, FAST).unwrap();
        change(&b, &mut b_vault, "from B");
        assert_eq!(run(&b, &cloud, UID, Mode::Push).unwrap(), Report::Uploaded);

        // A is behind: a push leaves its copy alone, a full sync brings B's change over.
        assert_eq!(
            run(&a, &cloud, UID, Mode::Push).unwrap(),
            Report::CloudNewer
        );
        assert_eq!(
            run(&a, &cloud, UID, Mode::Sync).unwrap(),
            Report::Downloaded
        );
        let Unlocked { vault, .. } = session::unlock(&a, "password1", None, FAST).unwrap();
        assert_eq!(vault.entries.len(), 1);
        assert_eq!(vault.entries[0].title, "from B");

        // And when A is the one ahead, it uploads.
        let mut vault = vault;
        change(&a, &mut vault, "from A");
        assert_eq!(run(&a, &cloud, UID, Mode::Sync).unwrap(), Report::Uploaded);
    }

    #[test]
    fn unrelated_vaults_are_never_overwritten_until_the_user_chooses() {
        let (a, _) = new_device("password one");
        let (b, _) = new_device("password two");
        let cloud = MemoryStore::new();
        run(&a, &cloud, UID, Mode::Sync).unwrap();
        let cloud_before = (
            cloud.get(Object::KeySlot).unwrap(),
            cloud.get(Object::Archive).unwrap(),
        );
        let b_before = (
            b.get(Object::KeySlot).unwrap(),
            b.get(Object::Archive).unwrap(),
        );

        assert_eq!(run(&b, &cloud, UID, Mode::Sync).unwrap(), Report::Unlinked);
        assert_eq!(run(&b, &cloud, UID, Mode::Push).unwrap(), Report::Unlinked);
        assert_eq!(
            (
                cloud.get(Object::KeySlot).unwrap(),
                cloud.get(Object::Archive).unwrap()
            ),
            cloud_before
        );
        assert_eq!(
            (
                b.get(Object::KeySlot).unwrap(),
                b.get(Object::Archive).unwrap()
            ),
            b_before
        );

        // Choosing the cloud vault replaces this device's: A's password now opens it.
        assert_eq!(
            run(&b, &cloud, UID, Mode::UseCloud).unwrap(),
            Report::Downloaded
        );
        assert!(session::unlock(&b, "password one", None, FAST).is_ok());
        assert_eq!(run(&b, &cloud, UID, Mode::Sync).unwrap(), Report::UpToDate);
    }

    #[test]
    fn keeping_this_devices_vault_replaces_the_cloud_one() {
        let (a, _) = new_device("password one");
        let (b, _) = new_device("password two");
        let cloud = MemoryStore::new();
        run(&a, &cloud, UID, Mode::Sync).unwrap();
        assert_eq!(
            run(&b, &cloud, UID, Mode::KeepLocal).unwrap(),
            Report::Uploaded
        );
        assert_eq!(
            cloud.get(Object::KeySlot).unwrap(),
            b.get(Object::KeySlot).unwrap()
        );
        assert_eq!(run(&b, &cloud, UID, Mode::Sync).unwrap(), Report::UpToDate);
    }

    #[test]
    fn equal_revisions_with_different_files_are_a_conflict_and_nothing_moves() {
        let (a, mut a_vault) = new_device("password1");
        let cloud = MemoryStore::new();
        run(&a, &cloud, UID, Mode::Sync).unwrap();
        let b = temp_store();
        run(&b, &cloud, UID, Mode::Sync).unwrap();
        let Unlocked {
            vault: mut b_vault, ..
        } = session::unlock(&b, "password1", None, FAST).unwrap();

        change(&a, &mut a_vault, "A");
        run(&a, &cloud, UID, Mode::Push).unwrap(); // cloud is at revision 2 from A
        change(&b, &mut b_vault, "B"); // B also made revision 2, from the same base

        let before = b.get(Object::Archive).unwrap();
        assert_eq!(run(&b, &cloud, UID, Mode::Sync).unwrap(), Report::Conflict);
        assert_eq!(b.get(Object::Archive).unwrap(), before);

        // B's next save is revision 3, which then wins.
        change(&b, &mut b_vault, "B again");
        assert_eq!(run(&b, &cloud, UID, Mode::Sync).unwrap(), Report::Uploaded);
    }

    #[test]
    fn an_older_cloud_copy_is_never_taken_over_a_newer_local_one_and_orphans_are_refused() {
        let (a, mut vault) = new_device("password1");
        let cloud = MemoryStore::new();
        run(&a, &cloud, UID, Mode::Sync).unwrap();
        let old_file = cloud.get(Object::Archive).unwrap().unwrap();
        change(&a, &mut vault, "newer");
        run(&a, &cloud, UID, Mode::Sync).unwrap();

        // A server replays the old file: this device is ahead, so it simply uploads over it again.
        cloud.put(Object::Archive, &old_file).unwrap();
        assert_eq!(run(&a, &cloud, UID, Mode::Sync).unwrap(), Report::Uploaded);

        // A vault file without a key slot is refused.
        let orphan = MemoryStore::new();
        orphan.put(Object::Archive, &old_file).unwrap();
        assert_eq!(
            run(&a, &orphan, UID, Mode::Sync).err(),
            Some(Error::Corrupt)
        );
    }

    #[test]
    fn an_old_pvlt_waiting_to_be_converted_is_not_replaced_by_a_cloud_download() {
        let (a, _) = new_device("password1");
        let cloud = MemoryStore::new();
        run(&a, &cloud, UID, Mode::Sync).unwrap();
        let b = temp_store();
        b.write_legacy(b"old vault bytes").unwrap();
        assert_eq!(run(&b, &cloud, UID, Mode::Sync).unwrap(), Report::Unlinked);
        assert!(b.has_legacy());
        assert!(!b.has(Object::KeySlot));
    }
}
