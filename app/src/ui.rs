//! The UI controller: wires Slint callbacks to the session, the JNI bridge and the background unlock thread.

use crate::bridge;
use crate::state::{self, AuthHow, Event};
use crate::{MainWindow, OtpRow, Row, Theme};
use silk_core::keyfile::{KeyFile, Login};
use silk_core::otp::{self, OtpParams};
use silk_core::session;
use silk_core::sync;
use silk_core::{auth, supabase};
use silk_core::{generate, new_id, transfer, Entry, Error, GenOptions, Kdf, Settings};
use slint::{ComponentHandle, Model, ModelRc, VecModel};
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

// Request codes shared with SilkActivity.java.
const KEY_PICK: i32 = 1;
const KEY_CREATE: i32 = 2;
const BACKUP_OUT: i32 = 3;
const BACKUP_IN: i32 = 4;
const IMPORT_IN: i32 = 5;
const EXPORT_CSV: i32 = 6;
const EXPORT_JSON: i32 = 7;

// Shared with Bio.java.
const BIO_ENROLL: i32 = 1;
const BIO_UNLOCK: i32 = 2;
const BIO_OK: i32 = 0;
const BIO_CANCELLED: i32 = 1;
const BIO_INVALIDATED: i32 = 3;

#[derive(Default)]
struct Ctl {
    creating: bool,
    /// True when this process was started by the autofill "Unlock Silk" row.
    auth_mode: bool,
    key_file: Option<Zeroizing<Vec<u8>>>,
    editing: Option<String>,
    otp: Option<OtpParams>,
    ticks: u32,
    /// App data directory (settings.json lives here).
    dir: PathBuf,
    settings: Settings,
    /// Which screen the login form returns to: 1 (logins) or 3 (codes).
    return_to: i32,
    /// The logins that have a one-time password, in the order the Codes list shows them.
    codes: Vec<(String, OtpParams)>,
    code_model: Rc<VecModel<OtpRow>>,
    /// The secret being typed on the Add authenticator screen.
    auth_otp: Option<OtpParams>,
    bio_enrolled: bool,
    /// A biometric prompt is on screen.
    bio_pending: bool,
    /// The lock screen already auto-prompted (or must not): stops prompt loops.
    bio_prompted: bool,
    /// The cloud sign-in saved in the key file (email, uid, refresh token), if the key file has one.
    login: Option<Login>,
    /// Signing in, or a sync the user asked for, is in flight.
    cloud_busy: bool,
    /// This device and the cloud account hold different vaults: the More screen asks which one to keep.
    cloud_choice: bool,
    /// A background upload failed (offline, usually): there are changes the cloud doesn't have yet.
    cloud_dirty: bool,
    /// The user asked for the sync in flight, so its result is announced. Background pushes stay quiet.
    explicit: bool,
}

type Shared = Rc<RefCell<Ctl>>;

/// Registers a no-argument Slint callback that gets the window and the controller state.
macro_rules! handler {
    ($ui:expr, $ctl:expr, $reg:ident, |$u:ident, $c:ident| $body:block) => {{
        let (weak, shared) = ($ui.as_weak(), $ctl.clone());
        $ui.$reg(move || {
            let $u = weak.unwrap();
            // Some handlers only read the state, so the `mut` is not needed in every expansion.
            #[allow(unused_mut)]
            let mut $c = shared.borrow_mut();
            $body
        });
    }};
}

pub fn run(dir: PathBuf) {
    state::session().set_dir(dir.clone());
    let ui = MainWindow::new().expect("create the window");
    let ctl: Shared = Rc::new(RefCell::new(Ctl::default()));
    {
        let mut c = ctl.borrow_mut();
        c.settings = Settings::load(&dir);
        c.dir = dir;
        // The Supabase project values; None while either of them is still a placeholder.
        state::set_cloud_config(
            bridge::cloud_config().and_then(|(url, key)| supabase::Config::new(&url, &key)),
        );
        apply_settings(&ui, &c.settings);
        ui.set_otp_rows(ModelRc::from(c.code_model.clone()));
        c.creating = !state::session().exists();
        c.auth_mode = bridge::is_autofill_request();
        ui.set_creating(c.creating);
        c.bio_enrolled = bridge::bio_enrolled();
        ui.set_bio_available(bridge::bio_available());
        ui.set_bio_enrolled(c.bio_enrolled);
        update_cloud_ui(&ui, &c);
    }
    ui.global::<Theme>().set_dark(bridge::is_dark());
    ui.set_autofill_on(bridge::autofill_enabled());
    ui.set_app_version(bridge::app_version().into());
    bridge::restore_key_file();
    wire(&ui, &ctl);
    let timer = slint::Timer::default();
    start_timer(&timer, &ui, &ctl);
    ui.run().expect("run the UI");
    // The activity is closing (Back): lock, so nothing stays unlocked behind a closed app.
    state::lock();
}

fn wire(ui: &MainWindow, ctl: &Shared) {
    ui.on_activity(state::touch);

    handler!(ui, ctl, on_submit, |ui, c| {
        let creating = c.creating;
        let mut pw = ui.get_pw1().to_string();
        if creating {
            if pw.chars().count() < 8 {
                ui.set_error("Use at least 8 characters for the master password.".into());
                return;
            }
            if pw != ui.get_pw2().as_str() {
                ui.set_error("The two passwords don't match.".into());
                return;
            }
        }
        ui.set_busy(true);
        ui.set_error("".into());
        state::touch();
        let key_file = c.key_file.as_ref().map(|k| Zeroizing::new(k.to_vec()));
        // Argon2 takes a moment, so it runs off the UI thread and reports back through an event.
        std::thread::spawn(move || {
            let result = unlock_or_create(&pw, key_file.as_ref().map(|k| k.as_slice()));
            pw.zeroize();
            state::push(Event::Unlocked(result.map_err(|e| e.to_string())));
        });
    });

    handler!(ui, ctl, on_bio_unlock, |ui, c| {
        start_bio_unlock(&ui, &mut c);
    });
    {
        let (weak, shared) = (ui.as_weak(), ctl.clone());
        ui.on_bio_set(move |on| {
            let ui = weak.unwrap();
            let mut c = shared.borrow_mut();
            state::touch();
            ui.set_error("".into());
            ui.set_notice("".into());
            if on {
                let key = state::session().export_vek();
                match key {
                    Ok(k) => {
                        c.bio_pending = true;
                        bridge::bio_enroll(&k[..]); // k is wiped when it drops
                    }
                    Err(Error::Locked) => lock_ui(&ui, &mut c),
                    Err(e) => ui.set_error(e.to_string().into()),
                }
                // Stay off until Android confirms.
                ui.set_bio_enrolled(c.bio_enrolled);
            } else {
                bridge::bio_disable();
                c.bio_enrolled = false;
                ui.set_bio_enrolled(false);
            }
        });
    }

    handler!(ui, ctl, on_pick_key_file, |_u, _c| {
        bridge::pick_file(KEY_PICK);
    });
    handler!(ui, ctl, on_create_key_file, |ui, _c| {
        // A Silk key file: a random 64-byte secret now, the cloud sign-in saved after it later.
        match KeyFile::generate() {
            Ok(kf) => {
                let bytes = Zeroizing::new(kf.to_bytes());
                bridge::create_file(KEY_CREATE, "silk.key", &bytes);
            }
            Err(e) => ui.set_error(e.to_string().into()),
        }
    });
    handler!(ui, ctl, on_clear_key_file, |ui, c| {
        c.key_file = None;
        c.login = None;
        ui.set_key_file_name("".into());
        bridge::forget_key_file();
        update_cloud_ui(&ui, &c);
    });
    handler!(ui, ctl, on_restore_backup, |_u, _c| {
        bridge::pick_file(BACKUP_IN);
    });
    handler!(ui, ctl, on_enable_autofill, |_u, _c| {
        bridge::open_autofill_settings();
    });
    handler!(ui, ctl, on_lock, |ui, c| {
        state::lock();
        lock_ui(&ui, &mut c);
    });
    handler!(ui, ctl, on_search, |ui, _c| {
        refresh_rows(&ui, &ui.get_query());
    });
    handler!(ui, ctl, on_backup, |ui, _c| {
        let file = state::session().read_backup();
        match file {
            Ok(bytes) => {
                ui.set_error("".into());
                ui.set_notice("".into());
                bridge::create_file(BACKUP_OUT, "silk-backup.silk", &bytes);
            }
            Err(e) => ui.set_error(e.to_string().into()),
        }
    });

    handler!(ui, ctl, on_new_login, |ui, c| {
        load_form(&ui, &mut c, None);
    });
    {
        let (weak, shared) = (ui.as_weak(), ctl.clone());
        ui.on_open_login(move |id| {
            let ui = weak.unwrap();
            let found = state::session()
                .entries()
                .and_then(|es| es.iter().find(|e| e.id == id.as_str()).cloned());
            match found {
                Some(e) => load_form(&ui, &mut shared.borrow_mut(), Some(e)),
                None => ui.set_error("That login no longer exists.".into()),
            }
        });
    }
    handler!(ui, ctl, on_back, |ui, c| {
        c.editing = None;
        c.otp = None;
        leave_form(&ui, &mut c);
    });
    handler!(ui, ctl, on_save, |ui, c| {
        let entry = Entry {
            id: c.editing.clone().unwrap_or_else(new_id),
            title: ui.get_f_title().trim().to_string(),
            username: ui.get_f_user().trim().to_string(),
            password: ui.get_f_password().to_string(),
            url: ui.get_f_url().trim().to_string(),
            otp: ui.get_f_otp().trim().to_string(),
            notes: ui.get_f_notes().to_string(),
        };
        let result = state::session().upsert(entry);
        if result.is_ok() {
            auto_backup();
        }
        match result {
            Ok(()) => {
                c.editing = None;
                c.otp = None;
                leave_form(&ui, &mut c);
            }
            Err(Error::Locked) => lock_ui(&ui, &mut c),
            Err(e) => ui.set_error(e.to_string().into()),
        }
    });
    handler!(ui, ctl, on_delete_login, |ui, c| {
        if let Some(id) = c.editing.take() {
            let result = state::session().remove(&id);
            if result.is_ok() {
                auto_backup();
            }
            match result {
                Ok(()) => {}
                Err(Error::Locked) => {
                    lock_ui(&ui, &mut c);
                    return;
                }
                Err(e) => {
                    ui.set_error(e.to_string().into());
                    return;
                }
            }
        }
        c.otp = None;
        leave_form(&ui, &mut c);
    });

    handler!(ui, ctl, on_generate, |ui, c| {
        ui.set_f_password(generate(&c.settings.generator).into());
        ui.set_show_password(true);
    });
    handler!(ui, ctl, on_copy_password, |ui, _c| {
        bridge::copy(&ui.get_f_password());
    });
    handler!(ui, ctl, on_copy_otp, |_u, c| {
        if let Some(p) = &c.otp {
            bridge::copy(&otp::code(p, now_secs()));
        }
    });
    handler!(ui, ctl, on_otp_edited, |ui, c| {
        let text = ui.get_f_otp();
        let parsed = otp::parse(&text);
        ui.set_otp_invalid(!text.trim().is_empty() && parsed.is_none());
        c.otp = parsed;
    });

    // ---- tabs ----
    {
        let (weak, shared) = (ui.as_weak(), ctl.clone());
        ui.on_go(move |screen| {
            let ui = weak.unwrap();
            let mut c = shared.borrow_mut();
            state::touch();
            ui.set_error("".into());
            ui.set_notice("".into());
            ui.set_export_ask(0);
            match screen {
                1 => refresh_rows(&ui, &ui.get_query()),
                3 => refresh_codes(&mut c),
                4 => show_preview(&ui, &c.settings.generator),
                _ => {}
            }
            ui.set_screen(screen);
        });
    }

    // ---- codes and authenticators ----
    {
        let shared = ctl.clone();
        ui.on_copy_code(move |id| {
            state::touch();
            let c = shared.borrow();
            if let Some((_, p)) = c.codes.iter().find(|(i, _)| i.as_str() == id.as_str()) {
                bridge::copy(&otp::code(p, now_secs()));
            }
        });
    }
    handler!(ui, ctl, on_new_authenticator, |ui, c| {
        clear_auth(&ui, &mut c);
        ui.set_error("".into());
        ui.set_notice("".into());
        ui.set_screen(6);
    });
    handler!(ui, ctl, on_auth_edited, |ui, c| {
        let text = ui.get_a_secret();
        let parsed = otp::parse(&text);
        ui.set_a_invalid(!text.trim().is_empty() && parsed.is_none());
        c.auth_otp = parsed;
        show_auth(&ui, &c);
    });
    handler!(ui, ctl, on_back_codes, |ui, c| {
        clear_auth(&ui, &mut c);
        refresh_codes(&mut c);
        ui.set_error("".into());
        ui.set_screen(3);
    });
    handler!(ui, ctl, on_save_authenticator, |ui, c| {
        let name = ui.get_a_name().trim().to_string();
        let secret = ui.get_a_secret().trim().to_string();
        if name.is_empty() || c.auth_otp.is_none() {
            return;
        }
        let entry = Entry {
            id: new_id(),
            title: name,
            otp: secret,
            ..Default::default()
        };
        let result = state::session().upsert(entry);
        if result.is_ok() {
            auto_backup();
        }
        match result {
            Ok(()) => {
                clear_auth(&ui, &mut c);
                refresh_codes(&mut c);
                ui.set_error("".into());
                ui.set_screen(3);
            }
            Err(Error::Locked) => lock_ui(&ui, &mut c),
            Err(e) => ui.set_error(e.to_string().into()),
        }
    });

    // ---- generator settings ----
    handler!(ui, ctl, on_gen_changed, |ui, c| {
        state::touch();
        c.settings.generator = GenOptions {
            length: ui.get_gen_length().max(0) as usize,
            lower: ui.get_gen_lower(),
            upper: ui.get_gen_upper(),
            digits: ui.get_gen_digits(),
            symbols: ui.get_gen_symbols(),
            avoid_lookalikes: ui.get_gen_lookalikes(),
        }
        .normalized();
        c.settings.auto_generate = ui.get_auto_generate();
        // Writes the cleaned-up values back (for example when every set was switched off) and a fresh preview.
        apply_settings(&ui, &c.settings);
        if let Err(e) = c.settings.save(&c.dir) {
            ui.set_error(e.to_string().into());
        }
    });
    handler!(ui, ctl, on_gen_regenerate, |ui, c| {
        state::touch();
        show_preview(&ui, &c.settings.generator);
    });
    handler!(ui, ctl, on_gen_copy, |ui, _c| {
        state::touch();
        bridge::copy(&ui.get_gen_preview());
        ui.set_notice("Copied. It is cleared from the clipboard after 5 minutes.".into());
    });

    // ---- cloud account and sync ----
    handler!(ui, ctl, on_cloud_sign_in, |ui, c| {
        start_account(&ui, &mut c, false);
    });
    handler!(ui, ctl, on_cloud_sign_up, |ui, c| {
        start_account(&ui, &mut c, true);
    });
    handler!(ui, ctl, on_cloud_sign_out, |ui, c| {
        state::touch();
        state::set_auth(None);
        let store = state::session().store();
        if let Ok(s) = store {
            let _ = s.unlink(); // the next sign-in starts from "never linked", so nothing is replaced unasked
        }
        c.login = None;
        c.cloud_choice = false;
        c.cloud_dirty = false;
        persist_login(&mut c); // removes the sign-in section from the key file
        update_cloud_ui(&ui, &c);
        ui.set_error("".into());
        ui.set_notice("Signed out. The vault on this device is unchanged and nothing was deleted from the cloud.".into());
    });
    handler!(ui, ctl, on_cloud_sync, |ui, c| {
        state::touch();
        ui.set_error("".into());
        ui.set_notice("".into());
        c.explicit = true;
        if state::signed_in() {
            if start_sync(sync::Mode::Sync) {
                c.cloud_busy = true;
            } else {
                c.explicit = false;
                ui.set_notice("A sync is already running. Try again in a moment.".into());
            }
        } else if start_resume(&mut c, true) {
            c.cloud_busy = true; // the sync follows as soon as the saved sign-in has been renewed
        } else {
            c.explicit = false;
            ui.set_screen(7);
        }
        update_cloud_ui(&ui, &c);
    });
    {
        let (weak, shared) = (ui.as_weak(), ctl.clone());
        ui.on_cloud_choose(move |keep_local| {
            let ui = weak.unwrap();
            let mut c = shared.borrow_mut();
            state::touch();
            ui.set_error("".into());
            c.cloud_choice = false;
            c.explicit = true;
            let mode = if keep_local {
                sync::Mode::KeepLocal
            } else {
                sync::Mode::UseCloud
            };
            if start_sync(mode) {
                c.cloud_busy = true;
            } else {
                c.explicit = false;
                c.cloud_choice = true;
                ui.set_notice("A sync is already running. Try again in a moment.".into());
            }
            update_cloud_ui(&ui, &c);
        });
    }

    // ---- Proton Pass import and export ----
    handler!(ui, ctl, on_import_proton, |ui, _c| {
        state::touch();
        ui.set_error("".into());
        ui.set_notice("".into());
        bridge::pick_file(IMPORT_IN);
    });
    {
        let weak = ui.as_weak();
        ui.on_export_file(move |kind| {
            let ui = weak.unwrap();
            state::touch();
            let list: Option<Vec<Entry>> = {
                let mut s = state::session();
                let copy: Option<Vec<Entry>> = s.entries().map(|e| e.to_vec());
                copy
            };
            let Some(mut list) = list else { return };
            let now = now_secs();
            let (mut bytes, code, name) = if kind == 2 {
                (
                    transfer::export_json(&list, now).into_bytes(),
                    EXPORT_JSON,
                    "silk-proton-pass.json",
                )
            } else {
                (
                    transfer::export_csv(&list, now).into_bytes(),
                    EXPORT_CSV,
                    "silk-proton-pass.csv",
                )
            };
            for e in list.iter_mut() {
                e.zeroize();
            }
            ui.set_error("".into());
            ui.set_notice("".into());
            bridge::create_file(code, name, &bytes);
            bytes.zeroize();
        });
    }
}

/// After every saved change: copies the encrypted backup (key slot + vault file) to the file chosen
/// with Backup or Restore, if there is one, and uploads to the cloud when signed in.
fn auto_backup() {
    let bytes = state::session().read_backup();
    if let Ok(b) = bytes {
        bridge::auto_backup(&b);
    }
    if state::signed_in() {
        start_sync(sync::Mode::Push);
    }
}

// ---- cloud: sign-in, the sign-in saved in the key file, and sync (all network work is on worker threads) ----

/// Writes `c.login` into the key file (or removes it when it is `None`). Only a Silk key file can hold
/// it: a raw key file is hashed whole, so writing into it would change the key. Returns whether it was saved.
fn persist_login(c: &mut Ctl) -> bool {
    let Some(raw) = c.key_file.as_ref() else {
        return false;
    };
    let Some(mut file) = KeyFile::parse(raw) else {
        return false;
    };
    file.set_login(c.login.clone());
    let bytes = Zeroizing::new(file.to_bytes());
    // Java verifies that the secret on disk is the same one before it writes anything after it.
    bridge::save_key_file(&bytes);
    c.key_file = Some(bytes);
    true
}

/// A key file was just loaded. With a saved sign-in in it, trade that for a session. Without one, a
/// sign-in made earlier in this run is saved into it, so the next start doesn't ask again.
fn adopt_login(ui: &MainWindow, c: &mut Ctl) {
    if c.auth_mode {
        return;
    }
    if c.login.is_some() {
        start_resume(c, false);
    } else if let Some(auth) = state::auth() {
        c.login = Some(auth.login());
        if !persist_login(c) {
            c.login = None;
        }
    }
    update_cloud_ui(ui, c);
}

/// Claims the sync slot and runs `mode` on a worker thread; the result comes back as `Event::Synced`.
/// Returns false when one is already running (a push is then queued behind it).
fn start_sync(mode: sync::Mode) -> bool {
    if !state::begin_sync() {
        return false;
    }
    std::thread::spawn(move || {
        let mut mode = mode;
        loop {
            let result = run_sync(mode);
            state::push(Event::Synced { mode, result });
            if !state::finish_sync() {
                break;
            }
            mode = sync::Mode::Push;
        }
    });
    true
}

fn run_sync(mode: sync::Mode) -> Result<sync::Report, Error> {
    let cfg =
        state::cloud_config().ok_or_else(|| Error::Remote("cloud sync isn't set up".into()))?;
    let auth = state::auth().ok_or(Error::SignedOut)?;
    let uid = auth.uid.clone();
    let store = state::session().store()?;
    let http = bridge::JavaHttp;
    let remote = supabase::SupabaseStore::new(&http, cfg, auth)?;
    let outcome = sync::run(&store, &remote, &uid, mode);
    // The access token may have been renewed on the way: keep the newest ones.
    state::set_auth(Some(remote.auth()));
    outcome
}

/// Trades the refresh token saved in the key file for a fresh session. `force` also retries when a
/// session exists. Returns false when there is nothing to resume (no saved sign-in, no cloud
/// config, or this is the autofill unlock screen, which never uses the network).
fn start_resume(c: &mut Ctl, force: bool) -> bool {
    if c.auth_mode {
        return false;
    }
    let (Some(cfg), Some(login)) = (state::cloud_config(), c.login.clone()) else {
        return false;
    };
    if !force && state::auth().map_or(false, |a| a.uid == login.uid) {
        return false; // already signed in as this account
    }
    std::thread::spawn(move || {
        let result = auth::refresh(&bridge::JavaHttp, &cfg, &login.email, &login.refresh_token);
        state::push(Event::CloudAuth {
            how: AuthHow::Resume,
            result,
        });
    });
    true
}

/// Sign in or create an account from the fields on the Cloud account screen.
fn start_account(ui: &MainWindow, c: &mut Ctl, sign_up: bool) {
    state::touch();
    ui.set_error("".into());
    ui.set_notice("".into());
    let Some(cfg) = state::cloud_config() else {
        ui.set_error(
            "Cloud sync isn't set up in this build. Fill in the Supabase values first (see docs/ARCHITECTURE.md).".into(),
        );
        return;
    };
    let email = ui.get_cloud_email().trim().to_string();
    let mut password = ui.get_cloud_pw().to_string();
    ui.set_cloud_pw("".into()); // the field is emptied as soon as the password has been taken
    if sign_up && password.chars().count() < 6 {
        password.zeroize();
        ui.set_error("Choose an account password of at least 6 characters.".into());
        return;
    }
    c.cloud_busy = true;
    update_cloud_ui(ui, c);
    std::thread::spawn(move || {
        let http = bridge::JavaHttp;
        let result = if sign_up {
            auth::sign_up(&http, &cfg, &email, &password)
        } else {
            auth::sign_in(&http, &cfg, &email, &password)
        };
        password.zeroize();
        let how = if sign_up {
            AuthHow::SignUp
        } else {
            AuthHow::SignIn
        };
        state::push(Event::CloudAuth { how, result });
    });
}

/// Refreshes everything on screen that depends on the cloud state.
fn update_cloud_ui(ui: &MainWindow, c: &Ctl) {
    let auth = state::auth();
    let email = auth
        .as_ref()
        .map(|a| a.email.clone())
        .or_else(|| c.login.as_ref().map(|l| l.email.clone()));
    let configured = state::cloud_config().is_some();
    let mut status = match (&email, auth.is_some(), c.login.is_some()) {
        _ if !configured => {
            "Cloud sync isn't set up in this build. The vault stays on this device.".to_string()
        }
        (None, _, _) => "Not signed in. The vault stays on this device.".to_string(),
        (Some(e), true, true) => {
            format!("Signed in as {e}. The sign-in is saved in your key file.")
        }
        (Some(e), true, false) => {
            format!("Signed in as {e} until Silk closes. Use a Silk key file (create one on the unlock screen) to stay signed in.")
        }
        (Some(e), false, _) => {
            format!("Signed in as {e}, but the cloud couldn't be reached yet. Unlocking still works from this device's copy.")
        }
    };
    if configured && email.is_some() && c.cloud_dirty {
        status += " Recent changes haven't reached the cloud yet; they upload on the next change or Sync now.";
    }
    if let Some(e) = &email {
        if ui.get_cloud_email().is_empty() {
            ui.set_cloud_email(e.as_str().into());
        }
    }
    ui.set_cloud_configured(configured);
    ui.set_cloud_linked(configured && email.is_some());
    ui.set_cloud_status(status.into());
    ui.set_cloud_busy(c.cloud_busy);
    ui.set_cloud_choice(c.cloud_choice);
}

/// The cloud vault replaced the local copy. What is open in memory is stale, so it is locked.
fn after_download(ui: &MainWindow, c: &mut Ctl, mode: sync::Mode) {
    c.cloud_choice = false;
    if mode == sync::Mode::UseCloud {
        // A different vault means a different VEK: the biometric key from before no longer fits.
        bridge::bio_disable();
        c.bio_enrolled = false;
        ui.set_bio_enrolled(false);
    }
    if ui.get_screen() != 0 {
        state::lock();
        lock_ui(ui, c);
        ui.set_notice(
            "Your vault was updated from the cloud. Enter your master password to open it.".into(),
        );
    } else {
        c.creating = false;
        ui.set_creating(false);
        ui.set_notice(
            "Found your vault in the cloud. Enter its master password to unlock it.".into(),
        );
    }
}

fn handle_cloud_auth(
    ui: &MainWindow,
    c: &mut Ctl,
    how: AuthHow,
    result: Result<auth::Auth, Error>,
) {
    let explicit = std::mem::take(&mut c.explicit);
    match (how, result) {
        (AuthHow::Resume, Ok(auth)) => {
            let login = auth.login();
            if c.login.as_ref() != Some(&login) {
                // The refresh token can rotate: keep the key file current.
                c.login = Some(login);
                persist_login(c);
            }
            state::set_auth(Some(auth));
            // At the lock screen the cloud copy may be newer (or this may be a new device): take it. Otherwise only push.
            let mode = if ui.get_screen() == 0 {
                sync::Mode::Sync
            } else {
                sync::Mode::Push
            };
            c.explicit = explicit;
            if start_sync(mode) {
                c.cloud_busy = explicit;
            } else {
                c.cloud_busy = false;
                c.explicit = false;
            }
        }
        (AuthHow::Resume, Err(Error::SignedOut)) => {
            c.cloud_busy = false;
            state::set_auth(None);
            c.login = None;
            persist_login(c);
            ui.set_notice(
                "Your cloud sign-in expired. Sign in again from More > Cloud sync.".into(),
            );
        }
        (AuthHow::Resume, Err(e)) => {
            // Offline or Supabase unreachable: stay quiet (unlocking works from the local copy) unless the user asked.
            c.cloud_busy = false;
            if explicit {
                ui.set_error(e.to_string().into());
            }
        }
        (_, Ok(auth)) => {
            c.cloud_busy = false;
            let email = auth.email.clone();
            c.login = Some(auth.login());
            state::set_auth(Some(auth));
            let saved = persist_login(c);
            if !saved {
                c.login = None; // not a Silk key file (or none loaded): the sign-in lasts until Silk closes
            }
            ui.set_error("".into());
            ui.set_notice(
                if saved {
                    format!("Signed in as {email}. The sign-in is saved in your key file.")
                } else {
                    format!("Signed in as {email} until Silk closes. To stay signed in, use a Silk key file (create one on the unlock screen).")
                }
                .into(),
            );
            ui.set_screen(5);
            // Link this device to the account. Anything that needs a decision is reported by the result.
            start_sync(sync::Mode::Sync);
        }
        (_, Err(e)) => {
            c.cloud_busy = false;
            ui.set_error(e.to_string().into());
        }
    }
    update_cloud_ui(ui, c);
}

fn handle_synced(
    ui: &MainWindow,
    c: &mut Ctl,
    mode: sync::Mode,
    result: Result<sync::Report, Error>,
) {
    c.cloud_busy = false;
    let explicit = mode != sync::Mode::Push && std::mem::take(&mut c.explicit);
    match result {
        Ok(report) => {
            c.cloud_dirty = false;
            match report {
                sync::Report::UpToDate if explicit => ui.set_notice("Already up to date.".into()),
                sync::Report::Uploaded if explicit => ui.set_notice("Synced. The cloud copy is up to date.".into()),
                sync::Report::UpToDate | sync::Report::Uploaded => {}
                sync::Report::Downloaded => after_download(ui, c, mode),
                sync::Report::CloudNewer => {
                    ui.set_notice("The cloud has a newer version of your vault. Use More > Sync now to bring it here.".into())
                }
                sync::Report::Conflict => ui.set_notice(
                    "Another device saved the vault at the same moment, so nothing was overwritten. Your next change replaces the cloud copy.".into(),
                ),
                sync::Report::Unlinked => {
                    c.cloud_choice = true;
                    ui.set_notice("Your cloud account already holds a different vault. Nothing was changed. Choose one in More > Cloud sync.".into());
                }
            }
        }
        Err(Error::SignedOut) => {
            state::set_auth(None);
            c.login = None;
            persist_login(c);
            ui.set_error(Error::SignedOut.to_string().into());
        }
        Err(e) => {
            if explicit {
                ui.set_error(e.to_string().into());
            } else {
                c.cloud_dirty = true; // offline is normal: the next change or Sync now uploads it
            }
        }
    }
    update_cloud_ui(ui, c);
}

/// Creates the vault on first use or opens the existing one. The slow
/// Argon2id work runs here, outside the session lock, so autofill is never held up behind it.
fn unlock_or_create(pw: &str, key_file: Option<&[u8]>) -> Result<(), Error> {
    let store = state::session().store()?;
    let vault = session::unlock(&store, pw, key_file, Kdf::default())?;
    state::session().install(vault)
}

/// Biometric unlock: the Keystore hands back the VEK, so there is no Argon2id.
fn unlock_with_vek(vek: &[u8; 32]) -> Result<(), Error> {
    let store = state::session().store()?;
    let vault = session::unlock_with_vek(&store, vek)?;
    state::session().install(vault)
}

fn start_bio_unlock(ui: &MainWindow, c: &mut Ctl) {
    if c.creating || !c.bio_enrolled || c.bio_pending || ui.get_busy() {
        return;
    }
    c.bio_pending = true;
    c.bio_prompted = true;
    ui.set_error("".into());
    bridge::bio_unlock();
}

fn start_timer(timer: &slint::Timer, ui: &MainWindow, ctl: &Shared) {
    let (weak, shared) = (ui.as_weak(), ctl.clone());
    timer.start(
        slint::TimerMode::Repeated,
        Duration::from_millis(250),
        move || {
            let ui = weak.unwrap();
            let mut c = shared.borrow_mut();
            for ev in state::drain() {
                handle_event(&ui, &mut c, ev);
            }
            // The session locks itself when idle; bring the UI back to the unlock screen.
            if ui.get_screen() != 0 && !state::session().is_unlocked() {
                lock_ui(&ui, &mut c);
            }
            if ui.get_screen() == 0 && c.bio_enrolled && !c.bio_prompted {
                start_bio_unlock(&ui, &mut c);
            }
            match ui.get_screen() {
                2 => show_otp(&ui, &c),
                3 => tick_codes(&c),
                6 => show_auth(&ui, &c),
                _ => {}
            }
            c.ticks = c.ticks.wrapping_add(1);
            if c.ticks % 8 == 0 {
                ui.set_autofill_on(bridge::autofill_enabled());
                c.bio_enrolled = bridge::bio_enrolled();
                ui.set_bio_enrolled(c.bio_enrolled);
            }
        },
    );
}

fn handle_event(ui: &MainWindow, c: &mut Ctl, ev: Event) {
    match ev {
        Event::CloudAuth { how, result } => handle_cloud_auth(ui, c, how, result),
        Event::Synced { mode, result } => handle_synced(ui, c, mode, result),
        Event::Unlocked(Ok(())) => {
            ui.set_busy(false);
            ui.set_pw1("".into());
            ui.set_pw2("".into());
            ui.set_error("".into());
            c.creating = false;
            ui.set_creating(false);
            if c.auth_mode {
                // Started by autofill: hand the matching logins back to the app that asked.
                bridge::finish_with_fill();
            } else {
                ui.set_notice("".into());
                ui.set_query("".into());
                refresh_rows(ui, "");
                ui.set_screen(1);
                if state::auth().is_none() {
                    // Offline at the lock screen, say: try the saved sign-in again now that the vault is open.
                    start_resume(c, false);
                }
            }
        }
        Event::Unlocked(Err(msg)) => {
            ui.set_busy(false);
            ui.set_error(msg.into());
        }
        Event::Bio { op, status, key } => {
            c.bio_pending = false;
            match op {
                BIO_ENROLL => {
                    if status == BIO_OK {
                        c.bio_enrolled = true;
                        ui.set_notice("Biometric unlock is on.".into());
                    } else if status != BIO_CANCELLED {
                        ui.set_error("Couldn't turn on biometric unlock.".into());
                    }
                    ui.set_bio_enrolled(c.bio_enrolled);
                }
                BIO_UNLOCK => match (status, key) {
                    (BIO_OK, Some(k)) if k.len() == 32 => {
                        let mut kk = Zeroizing::new([0u8; 32]);
                        kk.copy_from_slice(&k);
                        ui.set_busy(true);
                        ui.set_error("".into());
                        state::touch();
                        std::thread::spawn(move || {
                            let result = match unlock_with_vek(&kk) {
                                Ok(()) => Ok(()),
                                Err(Error::Corrupt) | Err(Error::NotAVault) => {
                                    bridge::bio_disable(); // the stored key no longer matches this vault
                                    Err("Biometric unlock is out of date. Use your master password.".to_string())
                                }
                                Err(e) => Err(e.to_string()),
                            };
                            state::push(Event::Unlocked(result));
                        });
                    }
                    (BIO_INVALIDATED, _) => {
                        c.bio_enrolled = false;
                        ui.set_bio_enrolled(false);
                        ui.set_error("Your biometrics changed, so biometric unlock was turned off. Use your master password.".into());
                    }
                    (BIO_CANCELLED, _) => {}
                    _ => ui.set_error(
                        "Biometric unlock didn't work. Use your master password.".into(),
                    ),
                },
                _ => {}
            }
        }
        Event::File {
            code,
            status,
            name,
            data,
        } => match (code, status) {
            (KEY_PICK | KEY_CREATE, 0) => {
                if let Some(d) = data {
                    // A Silk key file may carry the cloud sign-in saved by an earlier run.
                    c.login = KeyFile::parse(&d).and_then(|k| k.login().cloned());
                    c.key_file = Some(Zeroizing::new(d));
                    ui.set_key_file_name(name.unwrap_or_default().into());
                    ui.set_error("".into());
                    adopt_login(ui, c);
                }
            }
            (KEY_PICK | KEY_CREATE, 2) => {
                ui.set_error("Couldn't read that key file. Choose it again.".into())
            }
            (BACKUP_OUT, 0) => {
                ui.set_notice("Backup saved. This file now updates after every change.".into())
            }
            (BACKUP_OUT, 2) => {
                ui.set_error("Couldn't save the backup. Pick a different location.".into())
            }
            (BACKUP_IN, 0) => {
                if let Some(d) = data {
                    let imported = state::session().import(&d);
                    match imported {
                        Ok(()) => {
                            c.creating = false;
                            ui.set_creating(false);
                            ui.set_error("".into());
                            ui.set_notice(
                                "Backup restored. Enter its password to unlock it.".into(),
                            );
                            bridge::bio_disable();
                            c.bio_enrolled = false;
                            ui.set_bio_enrolled(false);
                        }
                        Err(e) => ui.set_error(e.to_string().into()),
                    }
                }
            }
            (BACKUP_IN, 2) => ui.set_error("Couldn't read that file.".into()),
            (IMPORT_IN, 0) => {
                if let Some(mut d) = data {
                    let parsed = transfer::import(&d);
                    d.zeroize();
                    match parsed {
                        Ok(imp) => finish_import(ui, c, imp),
                        Err(e) => {
                            ui.set_notice("".into());
                            ui.set_error(e.to_string().into());
                        }
                    }
                }
            }
            (IMPORT_IN, 2) => ui.set_error("Couldn't read that file.".into()),
            (EXPORT_CSV | EXPORT_JSON, 0) => ui.set_notice(
                "Exported. The file isn't encrypted: delete it once Proton Pass has imported it."
                    .into(),
            ),
            (EXPORT_CSV | EXPORT_JSON, 2) => {
                ui.set_error("Couldn't save the file. Pick a different location.".into())
            }
            _ => {}
        },
    }
}

fn lock_ui(ui: &MainWindow, c: &mut Ctl) {
    c.editing = None;
    c.otp = None;
    c.codes.clear();
    c.code_model.set_vec(Vec::<OtpRow>::new());
    clear_auth(ui, c);
    ui.set_export_ask(0);
    c.key_file = None; // wiped on drop; restored from the remembered location below
    c.login = None; // read again from the key file when it is restored
    c.bio_prompted = true;
    c.creating = false;
    clear_form(ui);
    ui.set_pw1("".into());
    ui.set_pw2("".into());
    ui.set_key_file_name("".into());
    ui.set_notice("".into());
    ui.set_error("".into());
    ui.set_busy(false);
    ui.set_creating(false);
    ui.set_screen(0);
    bridge::restore_key_file();
}

fn refresh_rows(ui: &MainWindow, query: &str) {
    let q = query.trim().to_lowercase();
    let rows: Vec<Row> = {
        let mut s = state::session();
        let list: Vec<Row> = match s.entries() {
            Some(entries) => {
                let mut found: Vec<&Entry> = entries
                    .iter()
                    .filter(|e| {
                        q.is_empty()
                            || e.title.to_lowercase().contains(&q)
                            || e.username.to_lowercase().contains(&q)
                            || e.url.to_lowercase().contains(&q)
                    })
                    .collect();
                found.sort_by_key(|e| e.title.to_lowercase());
                found
                    .into_iter()
                    .map(|e| Row {
                        id: e.id.as_str().into(),
                        title: e.title.as_str().into(),
                        subtitle: e.username.as_str().into(),
                    })
                    .collect()
            }
            None => Vec::new(),
        };
        list
    };
    ui.set_rows(ModelRc::new(VecModel::from(rows)));
}

fn load_form(ui: &MainWindow, c: &mut Ctl, entry: Option<Entry>) {
    c.editing = entry.as_ref().map(|x| x.id.clone());
    let e = entry.unwrap_or_default();
    ui.set_is_new(c.editing.is_none());
    ui.set_f_title(e.title.as_str().into());
    ui.set_f_user(e.username.as_str().into());
    ui.set_f_password(e.password.as_str().into());
    ui.set_f_url(e.url.as_str().into());
    ui.set_f_otp(e.otp.as_str().into());
    ui.set_f_notes(e.notes.as_str().into());
    ui.set_show_password(false);
    ui.set_otp_invalid(false);
    ui.set_error("".into());
    ui.set_notice("".into());
    c.otp = otp::parse(&e.otp);
    if c.editing.is_none() && c.settings.auto_generate {
        ui.set_f_password(generate(&c.settings.generator).into());
        ui.set_show_password(true);
    }
    let from = ui.get_screen();
    if from == 1 || from == 3 {
        c.return_to = from;
    }
    ui.set_screen(2);
}

fn clear_form(ui: &MainWindow) {
    ui.set_f_title("".into());
    ui.set_f_user("".into());
    ui.set_f_password("".into());
    ui.set_f_url("".into());
    ui.set_f_otp("".into());
    ui.set_f_notes("".into());
    ui.set_otp_code("".into());
    ui.set_show_password(false);
    ui.set_otp_invalid(false);
}

fn show_otp(ui: &MainWindow, c: &Ctl) {
    match &c.otp {
        Some(p) => {
            let now = now_secs();
            let left = otp::seconds_left(p, now);
            ui.set_otp_code(group(&otp::code(p, now)).into());
            ui.set_otp_left_text(format!("{left}s").into());
            ui.set_otp_progress(left as f32 / p.period as f32);
        }
        None => ui.set_otp_code("".into()),
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// "123456" -> "123 456", "12345678" -> "1234 5678".
fn group(code: &str) -> String {
    let n = if code.len() == 8 { 4 } else { 3 };
    code.as_bytes()
        .chunks(n)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Closes the login form and returns to the list it was opened from.
fn leave_form(ui: &MainWindow, c: &mut Ctl) {
    clear_form(ui);
    ui.set_error("".into());
    refresh_rows(ui, &ui.get_query());
    refresh_codes(c);
    ui.set_screen(if c.return_to == 3 { 3 } else { 1 });
}

fn apply_settings(ui: &MainWindow, s: &Settings) {
    let g = &s.generator;
    ui.set_gen_length(g.length as i32);
    ui.set_gen_lower(g.lower);
    ui.set_gen_upper(g.upper);
    ui.set_gen_digits(g.digits);
    ui.set_gen_symbols(g.symbols);
    ui.set_gen_lookalikes(g.avoid_lookalikes);
    ui.set_auto_generate(s.auto_generate);
    show_preview(ui, g);
}

fn show_preview(ui: &MainWindow, g: &GenOptions) {
    ui.set_gen_preview(generate(g).into());
    let bits = g.entropy_bits();
    let label = if bits < 50.0 {
        "weak"
    } else if bits < 70.0 {
        "fair"
    } else if bits < 100.0 {
        "strong"
    } else {
        "very strong"
    };
    ui.set_gen_strength(format!("About {bits:.0} bits of entropy, {label}").into());
}

fn code_row(id: &str, title: &str, user: &str, p: &OtpParams, now: u64) -> OtpRow {
    let left = otp::seconds_left(p, now);
    OtpRow {
        id: id.into(),
        title: title.into(),
        subtitle: user.into(),
        code: group(&otp::code(p, now)).into(),
        left_text: format!("{left}s").into(),
        progress: left as f32 / p.period as f32,
    }
}

/// Rebuilds the Codes list from the vault.
fn refresh_codes(c: &mut Ctl) {
    let mut found: Vec<(String, String, String, OtpParams)> = {
        let mut s = state::session();
        let list: Vec<(String, String, String, OtpParams)> = match s.entries() {
            Some(es) => es
                .iter()
                .filter_map(|e| {
                    otp::parse(&e.otp)
                        .map(|p| (e.id.clone(), e.title.clone(), e.username.clone(), p))
                })
                .collect(),
            None => Vec::new(),
        };
        list
    };
    found.sort_by_key(|f| f.1.to_lowercase());
    let now = now_secs();
    let rows: Vec<OtpRow> = found
        .iter()
        .map(|(id, title, user, p)| code_row(id, title, user, p, now))
        .collect();
    c.codes = found.into_iter().map(|(id, _, _, p)| (id, p)).collect();
    c.code_model.set_vec(rows);
}

/// Updates only the rows whose code or countdown text changed.
fn tick_codes(c: &Ctl) {
    let now = now_secs();
    for (i, (_, p)) in c.codes.iter().enumerate() {
        let Some(old) = c.code_model.row_data(i) else {
            continue;
        };
        let left = otp::seconds_left(p, now);
        let code = group(&otp::code(p, now));
        let left_text = format!("{left}s");
        if old.code.as_str() != code || old.left_text.as_str() != left_text {
            c.code_model.set_row_data(
                i,
                OtpRow {
                    code: code.into(),
                    left_text: left_text.into(),
                    progress: left as f32 / p.period as f32,
                    ..old
                },
            );
        }
    }
}

fn show_auth(ui: &MainWindow, c: &Ctl) {
    match &c.auth_otp {
        Some(p) => {
            let now = now_secs();
            let left = otp::seconds_left(p, now);
            ui.set_a_code(group(&otp::code(p, now)).into());
            ui.set_a_left_text(format!("{left}s").into());
            ui.set_a_progress(left as f32 / p.period as f32);
        }
        None => ui.set_a_code("".into()),
    }
}

fn clear_auth(ui: &MainWindow, c: &mut Ctl) {
    c.auth_otp = None;
    ui.set_a_name("".into());
    ui.set_a_secret("".into());
    ui.set_a_code("".into());
    ui.set_a_invalid(false);
}

fn finish_import(ui: &MainWindow, c: &mut Ctl, imp: transfer::Imported) {
    let result = state::session().merge_entries(imp.entries);
    if result.is_ok() {
        auto_backup();
    }
    match result {
        Ok((added, dups)) => {
            refresh_rows(ui, &ui.get_query());
            refresh_codes(c);
            ui.set_error("".into());
            let mut msg = format!(
                "Imported {added} {}.",
                if added == 1 { "login" } else { "logins" }
            );
            if dups > 0 {
                msg += &format!(" {dups} already in the vault, skipped.");
            }
            if imp.skipped > 0 {
                msg += &format!(" {} in the trash or empty, skipped.", imp.skipped);
            }
            if imp.passkeys > 0 {
                msg += &format!(
                    " {} passkey(s) can't be moved to another app.",
                    imp.passkeys
                );
            }
            ui.set_notice(msg.into());
        }
        Err(Error::Locked) => lock_ui(ui, c),
        Err(e) => ui.set_error(e.to_string().into()),
    }
}
