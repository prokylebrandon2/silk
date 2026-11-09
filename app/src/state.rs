//! Process-wide state shared by the UI thread and the JNI entry points (autofill runs on Java threads).
use silk_core::auth::Auth;
use silk_core::session::Session;
use silk_core::supabase;
use silk_core::{autofill, sync, Error};
use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard};

static SESSION: Mutex<Session> = Mutex::new(Session::new());
static EVENTS: Mutex<VecDeque<Event>> = Mutex::new(VecDeque::new());
static CLOUD: Mutex<Cloud> = Mutex::new(Cloud {
    config: None,
    auth: None,
    running: false,
    again: false,
});

/// The cloud side of the process: project values, the signed-in account's tokens, and the
/// "one sync at a time" latch. Network work runs on worker threads, never under the session lock.
struct Cloud {
    config: Option<supabase::Config>,
    auth: Option<Auth>,
    running: bool,
    /// Another push was asked for while one was running; one more run follows it.
    again: bool,
}

/// How an account session came about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthHow {
    SignIn,
    SignUp,
    /// The refresh token saved in the key file, traded for a fresh session.
    Resume,
}

/// Things that happen off the UI thread. The UI timer drains them.
pub enum Event {
    /// Result of signing in, creating an account, or resuming from the saved sign-in.
    CloudAuth {
        how: AuthHow,
        result: Result<Auth, Error>,
    },
    /// Result of one sync run (see `silk_core::sync`).
    Synced {
        mode: sync::Mode,
        result: Result<sync::Report, Error>,
    },
    /// A file picked or written through Android's document picker. `status`: 0 ok, 1 cancelled, 2 failed.
    File {
        code: i32,
        status: i32,
        name: Option<String>,
        data: Option<Vec<u8>>,
    },
    /// What the QR scanner brought back. `status`: 0 ok (`text` is the code's text), 1 cancelled, 2 failed.
    Scan { status: i32, text: Option<String> },
    /// Result of the background unlock or create.
    Unlocked(Result<(), String>),
    /// Result of a biometric prompt. `op`: 1 enroll, 2 unlock. `status`: 0 ok, 1 cancelled, 2 failed, 3 invalidated.
    Bio {
        op: i32,
        status: i32,
        key: Option<zeroize::Zeroizing<Vec<u8>>>,
    },
}

pub fn session() -> MutexGuard<'static, Session> {
    SESSION.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn push(e: Event) {
    EVENTS
        .lock()
        .unwrap_or_else(|x| x.into_inner())
        .push_back(e);
}

pub fn drain() -> Vec<Event> {
    EVENTS
        .lock()
        .unwrap_or_else(|x| x.into_inner())
        .drain(..)
        .collect()
}

pub fn lock() {
    session().lock();
}

fn cloud() -> MutexGuard<'static, Cloud> {
    CLOUD.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn set_cloud_config(config: Option<supabase::Config>) {
    cloud().config = config;
}

/// The project values, or `None` while any of them is still a placeholder.
pub fn cloud_config() -> Option<supabase::Config> {
    cloud().config.clone()
}

pub fn set_auth(auth: Option<Auth>) {
    cloud().auth = auth;
}

/// Keeps renewed tokens, but only while that same account is still signed in: a sign-out that happened
/// while a sync was running stays a sign-out.
pub fn renew_auth(auth: Auth) {
    let mut c = cloud();
    if c.auth.as_ref().map_or(false, |a| a.uid == auth.uid) {
        c.auth = Some(auth);
    }
}

/// A copy of the current account session (tokens are wiped when the copy drops).
pub fn auth() -> Option<Auth> {
    cloud().auth.clone()
}

pub fn signed_in() -> bool {
    cloud().auth.is_some()
}

/// Claims the single sync slot. `true`: the caller runs a sync and then calls [`finish_sync`].
/// `false`: one is already running; another push is queued to follow it.
pub fn begin_sync() -> bool {
    let mut c = cloud();
    if c.running {
        c.again = true;
        false
    } else {
        c.running = true;
        true
    }
}

/// `true` when a push was queued meanwhile (the slot stays claimed: run once more); `false` when idle again.
pub fn finish_sync() -> bool {
    let mut c = cloud();
    if c.again {
        c.again = false;
        true
    } else {
        c.running = false;
        false
    }
}

pub fn touch() {
    session().touch();
}

/// Autofill: flattened form JSON in, decision JSON out. Extends the session while the vault is open.
pub fn fill(request: &str) -> String {
    let mut s = session();
    let reply = autofill::handle(request, s.entries());
    if s.is_unlocked() {
        s.touch();
    }
    reply
}
