//! Silk core: vault file format, key derivation, TOTP and autofill matching.
//! Cloud architecture: `cloud` (unlock/save flow) -> `keyslot` (Argon2id key from `kdf` wraps the VEK) -> `archive`
//! (Kiln's `.skln`, through `skln`). `local` keeps the on-device copy of both
//! objects, `session` is the unlocked state the app holds, `backup` is the one-file backup.
//! Cloud: `auth` speaks Supabase Auth (who the user is) and `supabase` speaks Supabase Storage (the two
//! encrypted files, as a `RemoteStore`), both over a platform-provided `Http` trait; `sync` moves the two
//! objects between `local` and the cloud by revision;
//! `keyfile` is the key file layout that also carries the saved cloud sign-in.
//! No Android or UI code lives here, so everything is unit-tested on a normal machine.
#![forbid(unsafe_code)]

pub mod archive;
pub mod auth;
pub mod autofill;
pub mod backup;
pub mod cloud;
pub mod entry;
pub mod error;
pub mod generator;
pub mod kdf;
pub mod keyfile;
pub mod keyslot;
pub mod local;
pub mod otp;
pub mod remote;
pub mod session;
pub mod settings;
pub mod skln;
pub mod supabase;
pub mod sync;
pub mod transfer;

pub use cloud::CloudVault;
pub use entry::{new_id, Entry};
pub use error::Error;
pub use generator::{generate, GenOptions};
pub use kdf::Kdf;
pub use settings::Settings;
