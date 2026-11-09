//! JNI in both directions. Java calls `Native.fill/onFile/onScan/onBack/lock` (exported below); Rust calls the
//! public methods of `SilkActivity` on the running activity. Everything crossing the boundary is a string,
//! int, boolean or byte array.
use crate::state::{self, Event};
use jni::objects::{GlobalRef, JByteArray, JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jint};
use jni::{JNIEnv, JavaVM};
use silk_core::auth::{Http, HttpRequest, HttpResponse};
use silk_core::Error;
use std::sync::Mutex;

struct Bridge {
    vm: JavaVM,
    activity: GlobalRef,
}

static BRIDGE: Mutex<Option<Bridge>> = Mutex::new(None);

/// The window, for the phone's Back button: Java asks for it on its own thread and the step back
/// runs on the UI thread (see `Java_app_silk_Native_onBack`).
static WINDOW: Mutex<Option<slint::Weak<crate::MainWindow>>> = Mutex::new(None);

pub fn register_window(window: slint::Weak<crate::MainWindow>) {
    *WINDOW.lock().unwrap_or_else(|e| e.into_inner()) = Some(window);
}

pub fn init(app: &slint::android::AndroidApp) {
    // SAFETY: android-activity keeps both pointers valid for the life of the activity.
    let vm = unsafe { JavaVM::from_raw(app.vm_as_ptr().cast()) }.expect("JavaVM");
    let activity = {
        let env = vm.attach_current_thread().expect("attach to the JVM");
        let obj = unsafe { JObject::from_raw(app.activity_as_ptr().cast()) };
        env.new_global_ref(&obj)
            .expect("global ref to the activity")
    };
    // android_main runs again if the activity is recreated in the same process: keep the newest one.
    *BRIDGE.lock().unwrap_or_else(|e| e.into_inner()) = Some(Bridge { vm, activity });
}

fn with_env<R>(f: impl FnOnce(&mut JNIEnv, &JObject) -> jni::errors::Result<R>) -> Option<R> {
    let guard = BRIDGE.lock().unwrap_or_else(|e| e.into_inner());
    let b = guard.as_ref()?;
    let mut env = b.vm.attach_current_thread().ok()?;
    let out = f(&mut *env, b.activity.as_obj());
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_describe();
        let _ = env.exception_clear();
    }
    out.ok()
}

pub fn pick_file(code: i32) {
    with_env(|e, a| {
        e.call_method(a, "pickFile", "(I)V", &[JValue::Int(code)])
            .map(|_| ())
    });
}

pub fn create_file(code: i32, name: &str, data: &[u8]) {
    with_env(|e, a| {
        let n: JObject = e.new_string(name)?.into();
        let d: JObject = e.byte_array_from_slice(data)?.into();
        e.call_method(
            a,
            "createFile",
            "(ILjava/lang/String;[B)V",
            &[JValue::Int(code), JValue::Object(&n), JValue::Object(&d)],
        )
        .map(|_| ())
    });
}

/// Opens the QR scanner. The answer comes back as `Event::Scan`.
pub fn scan_qr() {
    with_env(|e, a| e.call_method(a, "scanQr", "()V", &[]).map(|_| ()));
}

/// Back from the first screen: the activity leaves the way it did before Back stepped through screens.
pub fn exit_app() {
    with_env(|e, a| e.call_method(a, "exitApp", "()V", &[]).map(|_| ()));
}

pub fn copy(text: &str) {
    with_env(|e, a| {
        let t: JObject = e.new_string(text)?.into();
        e.call_method(
            a,
            "copyToClipboard",
            "(Ljava/lang/String;)V",
            &[JValue::Object(&t)],
        )
        .map(|_| ())
    });
}

pub fn restore_key_file() {
    with_env(|e, a| e.call_method(a, "restoreKeyFile", "()V", &[]).map(|_| ()));
}

pub fn forget_key_file() {
    with_env(|e, a| e.call_method(a, "forgetKeyFile", "()V", &[]).map(|_| ()));
}

pub fn auto_backup(data: &[u8]) {
    with_env(|e, a| {
        let d: JObject = e.byte_array_from_slice(data)?.into();
        e.call_method(a, "autoBackup", "([B)V", &[JValue::Object(&d)])
            .map(|_| ())
    });
}

/// Writes the new key file bytes (with the saved cloud sign-in) into the remembered key file.
/// Java checks that the secret in the file on disk is the same before it touches anything.
pub fn save_key_file(data: &[u8]) {
    with_env(|e, a| {
        let d: JObject = e.byte_array_from_slice(data)?.into();
        e.call_method(a, "saveKeyFile", "([B)V", &[JValue::Object(&d)])
            .map(|_| ())
    });
}

/// `(Supabase project URL, Supabase publishable key)`, from `android/local.properties` or the
/// environment (see `android/app/build.gradle.kts`).
pub fn cloud_config() -> Option<(String, String)> {
    let raw = with_env(|e, a| {
        let v = e
            .call_method(a, "cloudConfig", "()Ljava/lang/String;", &[])?
            .l()?;
        let s: String = e.get_string(&JString::from(v))?.into();
        Ok(s)
    })?;
    let mut lines = raw.split('\n');
    let (url, publishable) = (lines.next()?, lines.next()?);
    Some((url.to_owned(), publishable.to_owned()))
}

/// The core's `Http` trait over `SilkActivity.http` (Java's `HttpURLConnection`). Blocking: call it from a worker thread.
pub struct JavaHttp;

impl Http for JavaHttp {
    fn send(&self, req: &HttpRequest) -> Result<HttpResponse, Error> {
        let headers = req
            .headers
            .iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect::<Vec<_>>()
            .join("\n");
        let reply = with_env(|e, a| {
            let m: JObject = e.new_string(req.method)?.into();
            let u: JObject = e.new_string(&req.url)?.into();
            let h: JObject = e.new_string(&headers)?.into();
            let b: JObject = e.byte_array_from_slice(&req.body)?.into();
            let r = e
                .call_method(
                    a,
                    "http",
                    "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[B)[B",
                    &[
                        JValue::Object(&m),
                        JValue::Object(&u),
                        JValue::Object(&h),
                        JValue::Object(&b),
                    ],
                )?
                .l()?;
            if r.as_raw().is_null() {
                return Ok(Vec::new());
            }
            let arr = JByteArray::from(r);
            e.convert_byte_array(&arr)
        });
        let bytes =
            reply.ok_or_else(|| Error::Remote("the network layer isn't available".into()))?;
        if bytes.len() < 2 {
            return Err(Error::Remote("no answer".into()));
        }
        // Two bytes of status, then the body. Status 0: no answer at all, the body says why.
        let status = u16::from_be_bytes([bytes[0], bytes[1]]);
        if status == 0 {
            return Err(Error::Remote(
                String::from_utf8_lossy(&bytes[2..]).into_owned(),
            ));
        }
        Ok(HttpResponse {
            status,
            body: bytes[2..].to_vec(),
        })
    }
}

pub fn finish_with_fill() {
    with_env(|e, a| e.call_method(a, "finishWithFill", "()V", &[]).map(|_| ()));
}

pub fn open_autofill_settings() {
    with_env(|e, a| {
        e.call_method(a, "openAutofillSettings", "()V", &[])
            .map(|_| ())
    });
}

fn call_bool(name: &str) -> bool {
    with_env(|e, a| e.call_method(a, name, "()Z", &[])?.z()).unwrap_or(false)
}

pub fn autofill_enabled() -> bool {
    call_bool("autofillEnabled")
}

pub fn is_dark() -> bool {
    call_bool("isDark")
}

/// Allows or blocks screenshots, screen recording and the recent-apps preview (`FLAG_SECURE`).
pub fn set_screenshots_allowed(allow: bool) {
    with_env(|e, a| {
        e.call_method(
            a,
            "setScreenshotsAllowed",
            "(Z)V",
            &[JValue::Bool(allow as u8)],
        )
        .map(|_| ())
    });
}

pub fn app_version() -> String {
    with_env(|e, a| {
        let v = e
            .call_method(a, "appVersion", "()Ljava/lang/String;", &[])?
            .l()?;
        let s: String = e.get_string(&JString::from(v))?.into();
        Ok(s)
    })
    .unwrap_or_default()
}

pub fn is_autofill_request() -> bool {
    call_bool("isAutofillRequest")
}

pub fn bio_available() -> bool {
    call_bool("bioAvailable")
}

pub fn bio_enrolled() -> bool {
    call_bool("bioEnrolled")
}

pub fn bio_unlock() {
    with_env(|e, a| e.call_method(a, "bioUnlock", "()V", &[]).map(|_| ()));
}

pub fn bio_disable() {
    with_env(|e, a| e.call_method(a, "bioDisable", "()V", &[]).map(|_| ()));
}

pub fn bio_enroll(key: &[u8]) {
    with_env(|e, a| {
        let k: JObject = e.byte_array_from_slice(key)?.into();
        e.call_method(a, "bioEnroll", "([B)V", &[JValue::Object(&k)])
            .map(|_| ())
    });
}

// ---- Java -> Rust ----

#[no_mangle]
pub extern "system" fn Java_app_silk_Native_fill<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    request: JString<'l>,
) -> JString<'l> {
    let req: String = env
        .get_string(&request)
        .map(String::from)
        .unwrap_or_default();
    let reply = state::fill(&req);
    env.new_string(reply)
        .unwrap_or_else(|_| JString::from(JObject::null()))
}

#[no_mangle]
pub extern "system" fn Java_app_silk_Native_onFile<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    code: jint,
    status: jint,
    name: JString<'l>,
    data: JByteArray<'l>,
) {
    let name = if name.as_raw().is_null() {
        None
    } else {
        env.get_string(&name).ok().map(String::from)
    };
    let data = if data.as_raw().is_null() {
        None
    } else {
        env.convert_byte_array(&data).ok()
    };
    state::push(Event::File {
        code,
        status,
        name,
        data,
    });
}

#[no_mangle]
pub extern "system" fn Java_app_silk_Native_onScan<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    status: jint,
    text: JString<'l>,
) {
    let text = if text.as_raw().is_null() {
        None
    } else {
        env.get_string(&text).ok().map(String::from)
    };
    state::push(Event::Scan { status, text });
}

/// The phone's Back button. Returns whether the UI took it: the step back (or the exit, from the first
/// screen) then happens on the UI thread, which is where the screens live. `false` means there is no
/// UI to ask, so Java does what Back always did.
#[no_mangle]
pub extern "system" fn Java_app_silk_Native_onBack<'l>(
    _env: JNIEnv<'l>,
    _class: JClass<'l>,
) -> jboolean {
    let window = WINDOW.lock().unwrap_or_else(|e| e.into_inner()).clone();
    match window {
        Some(w) => w
            .upgrade_in_event_loop(|ui| ui.invoke_system_back())
            .is_ok() as jboolean,
        None => 0,
    }
}

#[no_mangle]
pub extern "system" fn Java_app_silk_Native_lock<'l>(_env: JNIEnv<'l>, _class: JClass<'l>) {
    state::lock();
}

#[no_mangle]
pub extern "system" fn Java_app_silk_Native_onBio<'l>(
    env: JNIEnv<'l>,
    _class: JClass<'l>,
    op: jint,
    status: jint,
    key: JByteArray<'l>,
) {
    let key = if key.as_raw().is_null() {
        None
    } else {
        env.convert_byte_array(&key)
            .ok()
            .map(zeroize::Zeroizing::new)
    };
    state::push(Event::Bio { op, status, key });
}
