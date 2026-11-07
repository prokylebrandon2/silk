//! Silk core: vault file format, key derivation, TOTP and autofill matching.
//! Cloud architecture: `cloud` (unlock/save flow) -> `keyslot` (Argon2id key wraps the VEK) -> `archive`
//! (Kiln's `.skln`; `interim` stands in until it exists). `local` keeps the on-device copy of both
//! objects, `session` is the unlocked state the app holds, `backup` is the one-file backup.
//! Cloud: `firebase` speaks Auth (who the user is) and `supabase` speaks Storage (the two encrypted
//! files, as a `RemoteStore`), both over a platform-provided `Http` trait; `sync` moves the two
//! objects between `local` and the cloud by revision;
//! `keyfile` is the key file layout that also carries the saved cloud sign-in.
//! No Android or UI code lives here, so everything is unit-tested on a normal machine.
#![forbid(unsafe_code)]

pub mod archive;
pub mod autofill;
pub mod backup;
pub mod cloud;
pub mod error;
pub mod firebase;
pub mod generator;
pub mod interim;
pub mod keyfile;
pub mod keyslot;
pub mod local;
pub mod otp;
pub mod remote;
pub mod session;
pub mod settings;
pub mod supabase;
pub mod sync;
pub mod transfer;
pub mod vault;

pub use cloud::CloudVault;
pub use error::Error;
pub use generator::{generate, GenOptions};
pub use settings::Settings;
pub use vault::{generate_password, new_id, random_bytes, Entry, Kdf, Vault};
