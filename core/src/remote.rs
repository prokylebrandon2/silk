//! The cloud side of the architecture (Supabase Storage), seen from the core as a tiny key-value store.
//!
//! Two objects live in the cloud per user: the key slot and the vault file (Kiln's `.skln` archive
//! once it exists). The core never talks to the network itself; the platform layer provides a
//! [`RemoteStore`] (Supabase Storage over HTTPS on Android, see `supabase`). Everything stored here is already
//! encrypted, so the store is untrusted.
use crate::error::Error;
use std::collections::HashMap;
use std::sync::Mutex;

/// The two objects stored per user.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Object {
    /// The VEK, wrapped by the Argon2id key (`keyslot`).
    KeySlot,
    /// The encrypted archive holding the entries (see `archive`).
    Archive,
}

impl Object {
    /// File name under the user's folder, for example `vaults/<uid>/vault.skln` in Supabase Storage.
    pub fn file_name(self) -> &'static str {
        use crate::archive::Archiver;
        match self {
            Object::KeySlot => "keyslot.skvk",
            Object::Archive => crate::archive::current().file_name(),
        }
    }
}

pub trait RemoteStore {
    /// `Ok(None)` means "not there" (HTTP 404). Network or permission problems are `Err(Error::Remote(_))`,
    /// never `None`: the first-time setup path creates a new VEK, so a failed read must not look like a missing one.
    fn get(&self, object: Object) -> Result<Option<Vec<u8>>, Error>;
    fn put(&self, object: Object, data: &[u8]) -> Result<(), Error>;
    /// Removes the object. Removing one that isn't there is not an error. Nothing in the sync flow
    /// calls this; it exists for resetting an account's cloud copy.
    fn delete(&self, object: Object) -> Result<(), Error>;
    /// Whether the object is there. The default reads it, which is always correct; a store that can
    /// answer more cheaply may override it. Failures are errors, never `false`.
    fn exists(&self, object: Object) -> Result<bool, Error> {
        Ok(self.get(object)?.is_some())
    }
}

/// An in-memory store for tests and offline experiments.
#[derive(Default)]
pub struct MemoryStore {
    objects: Mutex<HashMap<Object, Vec<u8>>>,
}

impl MemoryStore {
    pub fn new() -> MemoryStore {
        MemoryStore::default()
    }
}

impl RemoteStore for MemoryStore {
    fn get(&self, object: Object) -> Result<Option<Vec<u8>>, Error> {
        Ok(self
            .objects
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&object)
            .cloned())
    }

    fn put(&self, object: Object, data: &[u8]) -> Result<(), Error> {
        self.objects
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(object, data.to_vec());
        Ok(())
    }

    fn delete(&self, object: Object) -> Result<(), Error> {
        self.objects
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&object);
        Ok(())
    }
}
