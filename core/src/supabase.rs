//! Supabase Storage over HTTPS, as the core sees it: the two encrypted objects per user, behind the
//! same one-method [`Http`] trait as the sign-in (`auth`).
//!
//! ```text
//! read    GET    <url>/storage/v1/object/authenticated/silk-vaults/vaults/<uid>/<file>
//! create  POST   <url>/storage/v1/object/silk-vaults/vaults/<uid>/<file>       (fails if it exists)
//! replace PUT    <url>/storage/v1/object/silk-vaults/vaults/<uid>/<file>
//! delete  DELETE <url>/storage/v1/object/silk-vaults/vaults/<uid>/<file>
//!
//! every call:  apikey: <publishable key>     Authorization: Bearer <Supabase access token>
//! ```
//!
//! **Who the user is.** The user signs in with Supabase Auth (`auth`), so the access token is
//! Supabase's own (`role: authenticated`, `sub` = the user id). The storage policies compare the
//! token's `sub` with the `<uid>` folder in the path. The path here is built from the signed-in
//! account only, never from a uid handed in separately, and a token whose `sub` is not that uid is
//! refused before anything is sent.
//!
//! **Untrusted storage.** Everything stored is already ciphertext. Neither the master password nor
//! any key ever reaches this module; it is handed the two finished byte buffers and nothing else.
//!
//! The access token and the Supabase key are never written into an [`Error`].
use crate::error::Error;
use crate::auth::{Account, Auth, Http, HttpRequest, HttpResponse};
use crate::remote::{Object, RemoteStore};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashSet;
use std::sync::Mutex;

/// The private bucket that holds every user's two files.
pub const BUCKET: &str = "silk-vaults";
const FOLDER: &str = "vaults";
const HOST_SUFFIX: &str = ".supabase.co";

// ---- configuration ----

/// The two values from the Supabase dashboard that the app needs: the project URL and the
/// **publishable** key. Neither is a secret; the Storage policies and the user's token decide access.
#[derive(Clone, PartialEq, Eq)]
pub struct Config {
    base: String,
    key: String,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("base", &self.base)
            .field("key", &"<hidden>")
            .finish()
    }
}

impl Config {
    /// `None` when a value is empty, still a `YOUR_...` placeholder, or not what it should be:
    /// - the URL must be `https://<project-ref>.supabase.co` (it is put into every request, and the
    ///   Java network layer only talks to this one host). The API addresses the dashboard shows next
    ///   to it (`.../rest/v1`, `.../auth/v1`, `.../storage/v1`) are accepted and cut back to the
    ///   project URL: pasting the wrong one of them is the easiest mistake to make here;
    /// - the key must not be a secret key. A `sb_secret_...` key or a legacy JWT key whose role is
    ///   not `anon` is refused, so a privileged key can't end up inside the app by mistake.
    pub fn new(url: &str, publishable_key: &str) -> Option<Config> {
        let url = url.trim().trim_end_matches('/');
        let url = ["/rest/v1", "/auth/v1", "/storage/v1"]
            .iter()
            .find_map(|api| url.strip_suffix(api))
            .unwrap_or(url);
        let key = publishable_key.trim();
        if url.starts_with("YOUR_") || key.starts_with("YOUR_") || key.is_empty() {
            return None;
        }
        let host = url.strip_prefix("https://")?;
        let project = host.strip_suffix(HOST_SUFFIX)?;
        let project_ok = !project.is_empty()
            && project
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
        let key_ok = key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
        if !project_ok || !key_ok || key.starts_with("sb_secret_") {
            return None;
        }
        if key.contains('.') {
            // A legacy JWT-style key: only the public `anon` one is acceptable.
            let claims = jwt_claims(key)?;
            if claims.get("role").and_then(Value::as_str) != Some("anon") {
                return None;
            }
        }
        Some(Config {
            base: format!("https://{host}"),
            key: key.to_owned(),
        })
    }

    /// The only host the app talks to, for the network layer's allow-list.
    pub fn host(&self) -> &str {
        self.base.strip_prefix("https://").unwrap_or(&self.base)
    }

    /// `https://<project-ref>.supabase.co`, no trailing slash.
    pub(crate) fn base(&self) -> &str {
        &self.base
    }

    pub(crate) fn key(&self) -> &str {
        &self.key
    }
}

// ---- reading tokens (never trusting them) ----

/// The claims of a JWT, without checking its signature: that is Supabase's job. Used to read the
/// `role` of a legacy API key and the `sub` of an access token.
fn jwt_claims(token: &str) -> Option<Value> {
    let mut parts = token.split('.');
    let (_header, payload, _sig) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    serde_json::from_slice(&b64url_decode(payload)?).ok()
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Refuses a token that is unreadable or that belongs to somebody else, before anything is sent.
/// The signature is Supabase's job; this only keeps the path and the token from disagreeing.
fn check_claims(token: &str, uid: &str) -> Result<(), Error> {
    let claims = jwt_claims(token).ok_or_else(|| {
        Error::Account("Supabase gave a sign-in token that Silk can't read.".into())
    })?;
    if claims.get("sub").and_then(Value::as_str) != Some(uid) {
        return Err(Error::SignedOut);
    }
    Ok(())
}

// ---- reading Storage's answers ----

/// What a Storage answer means. Storage has not always put the real status in the HTTP status: an
/// old behaviour answers `400` with `{"statusCode":"404", ...}` in the body, so the body is read first.
#[derive(Debug, PartialEq, Eq)]
enum Reply {
    Ok,
    NotFound,
    Duplicate,
    /// The token was refused (expired, or not accepted).
    TokenRejected,
    /// The policies said no.
    Denied,
    TooLarge,
    Other(u16, String),
}

#[derive(Deserialize, Default)]
struct ApiError {
    #[serde(default, rename = "statusCode")]
    status_code: Option<Value>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

fn classify(resp: &HttpResponse) -> Reply {
    if (200..300).contains(&resp.status) {
        return Reply::Ok;
    }
    let body: ApiError = serde_json::from_slice(&resp.body).unwrap_or_default();
    let code = match &body.status_code {
        Some(Value::String(s)) => s.trim().parse::<u16>().ok(),
        Some(Value::Number(n)) => n.as_u64().and_then(|n| u16::try_from(n).ok()),
        _ => None,
    }
    .unwrap_or(resp.status);
    let error = body.error.unwrap_or_default().to_ascii_lowercase();
    let message = body.message.unwrap_or_default();
    let lower = message.to_ascii_lowercase();

    if error == "invalidjwt"
        || lower.contains("jwt")
        || lower.contains("exp claim")
        || code == 401
        || resp.status == 401
    {
        return Reply::TokenRejected;
    }
    // A missing bucket is a set-up mistake, not "no vault yet".
    if lower.contains("bucket") {
        return Reply::Other(code, short(&message));
    }
    if code == 404 || error == "not_found" {
        return Reply::NotFound;
    }
    if code == 409 || error == "duplicate" {
        return Reply::Duplicate;
    }
    if code == 403 || lower.contains("row-level security") || error == "unauthorized" {
        return Reply::Denied;
    }
    if code == 413 || lower.contains("maximum allowed size") {
        return Reply::TooLarge;
    }
    Reply::Other(code, short(&message))
}

/// A short, single-line piece of Storage's own message, for the error text.
fn short(msg: &str) -> String {
    msg.chars().filter(|c| !c.is_control()).take(120).collect()
}

fn failure(reply: Reply) -> Error {
    match reply {
        Reply::TokenRejected => Error::SignedOut,
        Reply::Denied => Error::Remote(
            "Supabase refused the request. Check that supabase/storage-policies.sql has been run on the project."
                .into(),
        ),
        Reply::TooLarge => Error::Remote("The vault is larger than the cloud storage allows.".into()),
        Reply::NotFound => Error::Remote("Supabase Storage didn't find the bucket or the file.".into()),
        Reply::Duplicate => Error::Remote("The cloud file already exists.".into()),
        Reply::Other(code, msg) if msg.is_empty() => {
            Error::Remote(format!("Supabase Storage answered {code}"))
        }
        Reply::Other(code, msg) => Error::Remote(format!("Supabase Storage answered {code}: {msg}")),
        Reply::Ok => Error::Remote("unexpected answer".into()),
    }
}

// ---- the store ----

/// The signed-in user's two objects in Supabase Storage, as a [`RemoteStore`]. Renews the access
/// token when it has run out (and once more if Supabase rejects it), so a long-lived store keeps working.
pub struct SupabaseStore<'a> {
    http: &'a dyn Http,
    cfg: Config,
    account: Account<'a>,
    /// Objects this store has just been told are not there. A later "already exists" for one of
    /// them is a contradiction (it appeared meanwhile, or the policies hide it), so it is never
    /// replaced blindly.
    missing: Mutex<HashSet<Object>>,
}

impl<'a> SupabaseStore<'a> {
    /// Fails with `Error::Corrupt` when the uid isn't what Supabase hands out (it becomes part of the path).
    pub fn new(
        http: &'a dyn Http,
        cfg: Config,
        auth: Auth,
    ) -> Result<SupabaseStore<'a>, Error> {
        Ok(SupabaseStore {
            http,
            account: Account::new(http, cfg.clone(), auth)?,
            cfg,
            missing: Mutex::new(HashSet::new()),
        })
    }

    /// The current tokens. The refresh token can change during a sync, so callers read it back afterwards.
    pub fn auth(&self) -> Auth {
        self.account.auth()
    }

    fn path(&self, object: Object) -> String {
        format!("{FOLDER}/{}/{}", self.account.uid(), object.file_name())
    }

    fn url(&self, object: Object, read: bool) -> String {
        format!(
            "{}/storage/v1/object/{}{BUCKET}/{}",
            self.cfg.base,
            if read { "authenticated/" } else { "" },
            self.path(object)
        )
    }

    fn headers(&self, token: &str) -> Vec<(String, String)> {
        vec![
            ("apikey".into(), self.cfg.key.clone()),
            ("Authorization".into(), format!("Bearer {token}")),
        ]
    }

    fn missing(&self) -> std::sync::MutexGuard<'_, HashSet<Object>> {
        self.missing.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Sends the request built for the current token; if the token is rejected, renews it and tries once more.
    fn call(&self, make: impl Fn(&str) -> HttpRequest) -> Result<(Reply, HttpResponse), Error> {
        let mut renewed = false;
        loop {
            let token = self.account.token()?;
            check_claims(&token, &self.account.uid())?;
            let resp = self.http.send(&make(&token))?;
            let reply = classify(&resp);
            if reply == Reply::TokenRejected && !renewed {
                renewed = true;
                self.account.renew()?;
                continue;
            }
            return Ok((reply, resp));
        }
    }

    fn request(
        &self,
        method: &'static str,
        url: String,
        token: &str,
        extra: &[(&str, &str)],
        body: &[u8],
    ) -> HttpRequest {
        let mut headers = self.headers(token);
        headers.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        HttpRequest {
            method,
            url,
            headers,
            body: body.to_vec(),
        }
    }

    /// Uploads with `method`: `POST` creates (and refuses to replace), `PUT` replaces.
    fn upload(&self, method: &'static str, object: Object, data: &[u8]) -> Result<Reply, Error> {
        let url = self.url(object, false);
        let (reply, _) = self.call(|token| {
            self.request(
                method,
                url.clone(),
                token,
                // Not cached anywhere: sync decides by the revision it reads back, so a stale copy would
                // look like "this device is ahead".
                &[
                    ("Content-Type", "application/octet-stream"),
                    ("cache-control", "max-age=0"),
                ],
                data,
            )
        })?;
        Ok(reply)
    }
}

impl RemoteStore for SupabaseStore<'_> {
    fn get(&self, object: Object) -> Result<Option<Vec<u8>>, Error> {
        let url = self.url(object, true);
        let (reply, resp) = self.call(|token| {
            self.request(
                "GET",
                url.clone(),
                token,
                &[("Cache-Control", "no-cache")],
                &[],
            )
        })?;
        match reply {
            Reply::Ok => {
                self.missing().remove(&object);
                Ok(Some(resp.body))
            }
            Reply::NotFound => {
                self.missing().insert(object);
                Ok(None)
            }
            other => Err(failure(other)),
        }
    }

    fn put(&self, object: Object, data: &[u8]) -> Result<(), Error> {
        match self.upload("POST", object, data)? {
            Reply::Ok => {
                self.missing().remove(&object);
                Ok(())
            }
            Reply::Duplicate => {
                if self.missing().contains(&object) {
                    // We were just told it isn't there. Don't overwrite something we can't see.
                    return Err(Error::Remote(
                        "The cloud copy changed while syncing, so nothing was replaced. Sync again.".into(),
                    ));
                }
                match self.upload("PUT", object, data)? {
                    Reply::Ok => Ok(()),
                    other => Err(failure(other)),
                }
            }
            other => Err(failure(other)),
        }
    }

    fn delete(&self, object: Object) -> Result<(), Error> {
        let url = self.url(object, false);
        let (reply, _) = self.call(|token| self.request("DELETE", url.clone(), token, &[], &[]))?;
        match reply {
            Reply::Ok | Reply::NotFound => {
                self.missing().insert(object);
                Ok(())
            }
            other => Err(failure(other)),
        }
    }
}

// The mocked tests below never reach a real Supabase project. They check the requests this module
// builds and how it reacts to the answers Supabase is documented to give. Whether the live service
// answers the same way is checked by `supabase/smoke-test.ps1`.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::unix_now;
    use std::cell::{Cell, RefCell};
    use std::collections::{HashMap, VecDeque};

    const URL: &str = "https://abcdefghijklmnopqrst.supabase.co";
    const KEY: &str = "sb_publishable_testkey";
    const UID: &str = "uid123";

    fn b64(bytes: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let n = chunk.iter().fold(0u32, |a, b| (a << 8) | *b as u32) << (8 * (3 - chunk.len()));
            for i in 0..=chunk.len() {
                out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
            }
        }
        out
    }

    /// A JWT-shaped string with these claims (the signature part is fake: only Supabase checks it).
    fn jwt(claims: Value) -> String {
        format!(
            "{}.{}.sig",
            b64(br#"{"alg":"RS256"}"#),
            b64(claims.to_string().as_bytes())
        )
    }

    fn token(tag: &str) -> String {
        jwt(serde_json::json!({ "sub": UID, "role": "authenticated", "tag": tag }))
    }

    fn cfg() -> Config {
        Config::new(URL, KEY).unwrap()
    }

    fn auth_with(access_token: &str, expires_at: u64) -> Auth {
        Auth {
            email: "me@example.com".into(),
            uid: UID.into(),
            access_token: access_token.into(),
            refresh_token: "rt1".into(),
            expires_at,
        }
    }

    fn refresh_reply(access_token: &str) -> String {
        format!(
            r#"{{"access_token":"{access_token}","token_type":"bearer","expires_in":3600,"refresh_token":"rt2","user":{{"id":"{UID}","email":"me@example.com"}}}}"#
        )
    }

    /// Answers with the scripted responses in order and remembers what it was asked.
    struct Script {
        replies: RefCell<VecDeque<HttpResponse>>,
        seen: RefCell<Vec<HttpRequest>>,
    }

    impl Script {
        fn new(replies: Vec<(u16, String)>) -> Script {
            Script {
                replies: RefCell::new(
                    replies
                        .into_iter()
                        .map(|(status, body)| HttpResponse {
                            status,
                            body: body.into_bytes(),
                        })
                        .collect(),
                ),
                seen: RefCell::new(Vec::new()),
            }
        }
    }

    impl Http for Script {
        fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
            self.seen.borrow_mut().push(request.clone());
            self.replies
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| Error::Remote("script ran out".into()))
        }
    }

    fn s(status: u16, body: &str) -> (u16, String) {
        (status, body.to_string())
    }

    fn header<'a>(req: &'a HttpRequest, name: &str) -> Option<&'a str> {
        req.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    const NOT_FOUND: &str =
        r#"{"statusCode":"404","error":"not_found","message":"Object not found"}"#;
    const DUPLICATE: &str =
        r#"{"statusCode":"409","error":"Duplicate","message":"The resource already exists"}"#;
    const RLS: &str = r#"{"statusCode":"403","error":"Unauthorized","message":"new row violates row-level security policy"}"#;
    const EXPIRED: &str = r#"{"statusCode":"400","error":"InvalidJWT","message":"\"exp\" claim timestamp check failed"}"#;

    fn store<'a>(http: &'a dyn Http, access_token: &str) -> SupabaseStore<'a> {
        SupabaseStore::new(http, cfg(), auth_with(access_token, unix_now() + 3600)).unwrap()
    }

    // ---- configuration ----

    #[test]
    fn config_accepts_only_the_project_url_and_a_public_key() {
        assert_eq!(cfg().host(), "abcdefghijklmnopqrst.supabase.co");
        assert_eq!(
            Config::new(&format!(" {URL}/ "), KEY).unwrap().host(),
            "abcdefghijklmnopqrst.supabase.co"
        );
        for bad in [
            "",
            "YOUR_SUPABASE_URL",
            "http://abc.supabase.co",
            "https://abc.example.com",
            "https://abc.supabase.co/rest/v2",
            "https://abc.supabase.co/other/rest/v1x",
            "https://abc.supabase.co?x=1",
            "https://user@abc.supabase.co",
            "https://abc.supabase.co:8443",
            "https://a.b.supabase.co",
            "https://.supabase.co",
            "https://evil.com/.supabase.co",
        ] {
            assert!(Config::new(bad, KEY).is_none(), "{bad}");
        }
        for bad in ["", "YOUR_SUPABASE_KEY", "key with space", "k&x=1"] {
            assert!(Config::new(URL, bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn an_api_address_pasted_for_the_project_url_is_cut_back_to_the_project_url() {
        // The dashboard shows these next to the project URL; the first one is what ended up in a
        // real configuration and silently kept cloud sync switched off.
        for pasted in [
            format!("{URL}/rest/v1/"),
            format!("{URL}/rest/v1"),
            format!("{URL}/auth/v1"),
            format!(" {URL}/storage/v1/ "),
        ] {
            let c = Config::new(&pasted, KEY).unwrap_or_else(|| panic!("{pasted}"));
            assert_eq!(c.base(), URL, "{pasted}");
            assert_eq!(c.host(), "abcdefghijklmnopqrst.supabase.co");
        }
        // Still only a Supabase project host after the cut.
        assert!(Config::new("https://evil.com/rest/v1", KEY).is_none());
        assert!(Config::new("https://abc.example.com/auth/v1", KEY).is_none());
    }

    #[test]
    fn config_refuses_secret_keys() {
        assert!(Config::new(URL, "sb_secret_abcdef").is_none());
        let service = jwt(serde_json::json!({ "role": "service_role" }));
        assert!(Config::new(URL, &service).is_none());
        let anon = jwt(serde_json::json!({ "role": "anon" }));
        assert!(Config::new(URL, &anon).is_some());
        // A JWT-shaped key that can't be read is not trusted either.
        assert!(Config::new(URL, "aaa.bbb.ccc").is_none());
        // The key never shows up when the config is printed.
        assert!(!format!("{:?}", cfg()).contains("testkey"));
    }

    // ---- request construction and paths ----

    #[test]
    fn reads_go_to_the_users_own_folder_with_both_credentials() {
        let tok = token("a");
        let http = Script::new(vec![s(404, NOT_FOUND), s(200, "ciphertext")]);
        let st = store(&http, &tok);
        assert_eq!(st.get(Object::KeySlot).unwrap(), None);
        assert_eq!(st.get(Object::KeySlot).unwrap().unwrap(), b"ciphertext");
        let seen = http.seen.borrow();
        assert_eq!(seen[0].method, "GET");
        assert_eq!(
            seen[0].url,
            format!("{URL}/storage/v1/object/authenticated/silk-vaults/vaults/uid123/keyslot.skvk")
        );
        assert_eq!(header(&seen[0], "apikey"), Some(KEY));
        assert_eq!(
            header(&seen[0], "Authorization"),
            Some(format!("Bearer {tok}").as_str())
        );
        // Nothing else is sent along, and nothing in the body.
        assert!(seen[0].body.is_empty());
    }

    #[test]
    fn both_objects_use_their_own_file_names() {
        let http = Script::new(vec![s(200, "{}"), s(200, "{}")]);
        let st = store(&http, &token("a"));
        st.put(Object::KeySlot, b"s").unwrap();
        st.put(Object::Archive, b"v").unwrap();
        let seen = http.seen.borrow();
        assert!(seen[0]
            .url
            .ends_with("/silk-vaults/vaults/uid123/keyslot.skvk"));
        assert!(seen[1].url.ends_with(&format!(
            "/silk-vaults/vaults/uid123/{}",
            Object::Archive.file_name()
        )));
    }

    #[test]
    fn the_path_always_comes_from_the_signed_in_account() {
        let http = Script::new(vec![]);
        // A uid that could change the path is refused up front.
        for bad in ["../other", "a/b", "", "a b", "x?y=1"] {
            let mut a = auth_with(&token("a"), unix_now() + 3600);
            a.uid = bad.into();
            assert!(
                SupabaseStore::new(&http, cfg(), a).is_err(),
                "{bad}"
            );
        }
        // A token that belongs to somebody else is refused before anything is sent.
        let other = jwt(serde_json::json!({ "sub": "someone-else", "role": "authenticated" }));
        let st = store(&http, &other);
        assert_eq!(st.get(Object::KeySlot).err(), Some(Error::SignedOut));
        assert!(http.seen.borrow().is_empty());
    }

    #[test]
    fn a_token_that_cannot_be_read_stops_before_any_request() {
        let http = Script::new(vec![]);
        for t in ["not-a-jwt", "a.b", "a.b.c.d", "a.%%%.c"] {
            let st = store(&http, t);
            assert!(
                matches!(st.get(Object::KeySlot), Err(Error::Account(_))),
                "{t}"
            );
            assert!(matches!(
                st.put(Object::KeySlot, b"x"),
                Err(Error::Account(_))
            ));
            assert!(matches!(st.delete(Object::KeySlot), Err(Error::Account(_))));
        }
        assert!(http.seen.borrow().is_empty());
    }

    // ---- reading answers ----

    #[test]
    fn a_missing_object_is_none_in_either_of_the_shapes_storage_uses() {
        let http = Script::new(vec![s(404, NOT_FOUND), s(400, NOT_FOUND)]);
        let st = store(&http, &token("a"));
        assert_eq!(st.get(Object::Archive).unwrap(), None);
        assert_eq!(st.get(Object::Archive).unwrap(), None);
    }

    #[test]
    fn a_failed_read_is_an_error_never_none() {
        // The first-time setup path creates a new VEK on "not there", so none of these may look like that.
        let missing_bucket =
            r#"{"statusCode":"404","error":"Bucket not found","message":"Bucket not found"}"#;
        let http = Script::new(vec![
            s(403, RLS),
            s(400, RLS),
            s(500, "oops"),
            s(502, ""),
            s(400, missing_bucket),
        ]);
        let st = store(&http, &token("a"));
        for _ in 0..5 {
            assert!(matches!(st.get(Object::Archive), Err(Error::Remote(_))));
        }
    }

    #[test]
    fn permission_denied_gets_a_readable_message() {
        let http = Script::new(vec![s(403, RLS), s(400, RLS)]);
        let st = store(&http, &token("a"));
        for _ in 0..2 {
            match st.put(Object::KeySlot, b"x") {
                Err(Error::Remote(m)) => {
                    assert!(m.contains("refused") && m.contains("policies"), "{m}")
                }
                other => panic!("{other:?}"),
            }
        }
        // Too large is its own message.
        let big = Script::new(vec![s(
            413,
            r#"{"statusCode":"413","error":"Payload too large","message":"The object exceeded the maximum allowed size"}"#,
        )]);
        match store(&big, &token("a")).put(Object::Archive, b"x") {
            Err(Error::Remote(m)) => assert!(m.contains("larger"), "{m}"),
            other => panic!("{other:?}"),
        }
    }

    // ---- writing ----

    #[test]
    fn a_new_object_is_created_not_upserted_and_carries_exactly_the_bytes_given() {
        let tok = token("a");
        let http = Script::new(vec![s(
            200,
            r#"{"Key":"silk-vaults/vaults/uid123/keyslot.skvk"}"#,
        )]);
        let st = store(&http, &tok);
        st.put(Object::KeySlot, b"slot-bytes").unwrap();
        let seen = http.seen.borrow();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].method, "POST");
        assert_eq!(
            seen[0].url,
            format!("{URL}/storage/v1/object/silk-vaults/vaults/uid123/keyslot.skvk")
        );
        assert_eq!(seen[0].body, b"slot-bytes");
        assert_eq!(
            header(&seen[0], "Content-Type"),
            Some("application/octet-stream")
        );
        assert_eq!(header(&seen[0], "x-upsert"), None);
        assert_eq!(header(&seen[0], "cache-control"), Some("max-age=0"));
    }

    #[test]
    fn an_existing_object_is_replaced_with_put_after_it_was_seen() {
        let http = Script::new(vec![s(200, "old"), s(409, DUPLICATE), s(200, "{}")]);
        let st = store(&http, &token("a"));
        assert!(st.get(Object::Archive).unwrap().is_some());
        st.put(Object::Archive, b"new").unwrap();
        let seen = http.seen.borrow();
        assert_eq!(
            seen.iter().map(|r| r.method).collect::<Vec<_>>(),
            ["GET", "POST", "PUT"]
        );
        assert_eq!(seen[2].body, b"new");
        assert_eq!(seen[1].url.replace("authenticated/", ""), seen[2].url);
    }

    #[test]
    fn an_object_that_was_just_reported_missing_is_never_overwritten() {
        // Missing, then "already exists": a contradiction (it appeared, or the policies hide it).
        for dup in [s(409, DUPLICATE), s(400, DUPLICATE)] {
            let http = Script::new(vec![s(404, NOT_FOUND), dup]);
            let st = store(&http, &token("a"));
            assert_eq!(st.get(Object::KeySlot).unwrap(), None);
            assert!(matches!(
                st.put(Object::KeySlot, b"x"),
                Err(Error::Remote(_))
            ));
            assert!(http.seen.borrow().iter().all(|r| r.method != "PUT"));
        }
    }

    #[test]
    fn delete_removes_the_object_and_a_missing_one_is_fine() {
        let http = Script::new(vec![s(200, "[]"), s(404, NOT_FOUND), s(403, RLS)]);
        let st = store(&http, &token("a"));
        st.delete(Object::Archive).unwrap();
        st.delete(Object::Archive).unwrap();
        assert!(st.delete(Object::Archive).is_err());
        let seen = http.seen.borrow();
        assert_eq!(seen[0].method, "DELETE");
        assert_eq!(
            seen[0].url,
            format!(
                "{URL}/storage/v1/object/silk-vaults/vaults/uid123/{}",
                Object::Archive.file_name()
            )
        );
    }

    #[test]
    fn exists_reads_and_reports_failures_as_errors() {
        let http = Script::new(vec![s(200, "x"), s(404, NOT_FOUND), s(500, "")]);
        let st = store(&http, &token("a"));
        assert!(st.exists(Object::KeySlot).unwrap());
        assert!(!st.exists(Object::KeySlot).unwrap());
        assert!(st.exists(Object::KeySlot).is_err());
    }

    // ---- tokens ----

    #[test]
    fn an_expired_token_is_renewed_before_the_call_and_the_new_one_is_used() {
        let fresh = token("fresh");
        let http = Script::new(vec![s(200, &refresh_reply(&fresh)), s(200, "data")]);
        let st = SupabaseStore::new(&http, cfg(), auth_with(&token("old"), 0)).unwrap();
        assert_eq!(st.get(Object::Archive).unwrap().unwrap(), b"data");
        let seen = http.seen.borrow();
        assert_eq!(
            seen[0].url,
            format!("{URL}/auth/v1/token?grant_type=refresh_token")
        );
        assert_eq!(
            header(&seen[1], "Authorization"),
            Some(format!("Bearer {fresh}").as_str())
        );
        assert_eq!(st.auth().refresh_token, "rt2");
    }

    #[test]
    fn a_rejected_token_is_renewed_once_in_either_of_the_shapes_storage_uses() {
        for rejected in [s(401, "{}"), s(400, EXPIRED)] {
            let fresh = token("fresh");
            let http = Script::new(vec![
                rejected,
                s(200, &refresh_reply(&fresh)),
                s(200, "data"),
            ]);
            let st = store(&http, &token("old"));
            assert_eq!(st.get(Object::Archive).unwrap().unwrap(), b"data");
            assert_eq!(http.seen.borrow().len(), 3);
        }
        // Still rejected after the renewal: signed out.
        let fresh = token("fresh");
        let http = Script::new(vec![
            s(400, EXPIRED),
            s(200, &refresh_reply(&fresh)),
            s(400, EXPIRED),
        ]);
        let st = store(&http, &token("old"));
        assert_eq!(st.get(Object::Archive).err(), Some(Error::SignedOut));
        // A refresh token Supabase no longer accepts: signed out as well.
        let http = Script::new(vec![
            s(401, "{}"),
            s(
                400,
                r#"{"code":400,"error_code":"refresh_token_not_found","msg":"Invalid Refresh Token: Refresh Token Not Found"}"#,
            ),
        ]);
        let st = store(&http, &token("old"));
        assert_eq!(st.get(Object::Archive).err(), Some(Error::SignedOut));
    }

    #[test]
    fn nothing_secret_ends_up_in_an_error_message() {
        let tok = token("secret-tag");
        let cases = [
            s(403, RLS),
            s(500, "oops"),
            s(400, EXPIRED),
            s(404, NOT_FOUND),
        ];
        for case in cases {
            let http = Script::new(vec![case, s(500, "x"), s(500, "x")]);
            let st = store(&http, &tok);
            for e in [
                st.get(Object::KeySlot).err(),
                st.put(Object::KeySlot, b"x").err(),
                st.delete(Object::KeySlot).err(),
            ]
            .into_iter()
            .flatten()
            {
                let text = format!("{e} {e:?}");
                assert!(
                    !text.contains(&tok) && !text.contains("secret-tag") && !text.contains(KEY)
                );
            }
        }
    }

    // ---- a whole sync against a pretend Supabase ----

    /// Pretends to be Supabase Storage with one in-memory bucket.
    struct World {
        objects: RefCell<HashMap<String, Vec<u8>>>,
        seen: RefCell<Vec<HttpRequest>>,
        /// Answer every write with an RLS refusal.
        deny_writes: Cell<bool>,
        /// Use the old shape that puts the real status in the body of a `400`.
        quirky: bool,
    }

    impl World {
        fn new(quirky: bool) -> World {
            World {
                objects: RefCell::new(HashMap::new()),
                seen: RefCell::new(Vec::new()),
                deny_writes: Cell::new(false),
                quirky,
            }
        }

        fn reply(&self, status: u16, body: &str) -> Result<HttpResponse, Error> {
            // The old shape: the status in the body, a 400 on the wire.
            let status = if self.quirky && status >= 400 && status != 500 {
                400
            } else {
                status
            };
            Ok(HttpResponse {
                status,
                body: body.as_bytes().to_vec(),
            })
        }

        fn uploads(&self) -> Vec<HttpRequest> {
            self.seen
                .borrow()
                .iter()
                .filter(|r| r.method == "POST" || r.method == "PUT")
                .cloned()
                .collect()
        }
    }

    impl Http for World {
        fn send(&self, req: &HttpRequest) -> Result<HttpResponse, Error> {
            self.seen.borrow_mut().push(req.clone());
            let prefix = format!("{URL}/storage/v1/object/");
            let rest = req
                .url
                .strip_prefix(&prefix)
                .expect("only the Supabase host");
            let rest = rest.strip_prefix("authenticated/").unwrap_or(rest);
            let path = rest
                .strip_prefix("silk-vaults/")
                .expect("only the silk-vaults bucket")
                .to_string();
            let mut objects = self.objects.borrow_mut();
            let writing = req.method != "GET";
            if writing && self.deny_writes.get() {
                return self.reply(403, RLS);
            }
            match (req.method, objects.contains_key(&path)) {
                ("GET", true) => Ok(HttpResponse {
                    status: 200,
                    body: objects[&path].clone(),
                }),
                ("GET", false) => self.reply(404, NOT_FOUND),
                ("POST", true) => self.reply(409, DUPLICATE),
                ("POST", false) | ("PUT", true) => {
                    objects.insert(path, req.body.clone());
                    self.reply(200, "{}")
                }
                ("PUT", false) => self.reply(404, NOT_FOUND),
                ("DELETE", _) => {
                    objects.remove(&path);
                    self.reply(200, "[]")
                }
                _ => panic!("unexpected request"),
            }
        }
    }

    mod flow {
        use super::*;
        use crate::local::DirStore;
        use crate::session::{self, Unlocked};
        use crate::sync::{self, Mode, Report};
        use crate::vault::{new_id, Entry, Kdf};

        const FAST: Kdf = Kdf {
            t: 1,
            mem_kib: 64,
            p: 1,
        };
        const MASTER: &str = "correct horse battery staple";
        const LOGIN_PASSWORD: &str = "S3cretLoginPassw0rd!";

        fn device() -> DirStore {
            DirStore::new(std::env::temp_dir().join(format!("silk-supabase-{}", new_id())))
        }

        fn login(title: &str) -> Entry {
            Entry {
                id: new_id(),
                title: title.into(),
                username: "alice@example.com".into(),
                password: LOGIN_PASSWORD.into(),
                url: "https://bank.example.com".into(),
                notes: "recovery phrase: purple elephant".into(),
                ..Entry::default()
            }
        }

        fn contains(hay: &[u8], needle: &str) -> bool {
            let n = needle.as_bytes();
            hay.windows(n.len()).any(|w| w == n)
        }

        #[test]
        fn sync_uploads_then_a_second_device_downloads_through_the_supabase_protocol() {
            for quirky in [false, true] {
                let world = World::new(quirky);
                let tok = token("a");
                let a = device();
                let Unlocked { mut vault, .. } = session::unlock(&a, MASTER, None, FAST).unwrap();
                vault.upsert(login("Bank"));
                vault.save_remote(&a).unwrap();

                let st = store(&world, &tok);
                assert_eq!(
                    sync::run(&a, &st, UID, Mode::Sync).unwrap(),
                    Report::Uploaded
                );
                assert_eq!(world.objects.borrow().len(), 2);
                assert_eq!(
                    sync::run(&a, &st, UID, Mode::Sync).unwrap(),
                    Report::UpToDate
                );

                // A second device with the same account gets the vault and opens it.
                let b = device();
                assert_eq!(
                    sync::run(&b, &st, UID, Mode::Sync).unwrap(),
                    Report::Downloaded
                );
                let Unlocked { vault, .. } = session::unlock(&b, MASTER, None, FAST).unwrap();
                assert_eq!(vault.entries[0].title, "Bank");

                // Device B saves; the replace goes through PUT and A picks it up.
                let Unlocked { mut vault, .. } = session::unlock(&b, MASTER, None, FAST).unwrap();
                vault.upsert(login("Mail"));
                vault.save_remote(&b).unwrap();
                assert_eq!(
                    sync::run(&b, &st, UID, Mode::Push).unwrap(),
                    Report::Uploaded
                );
                assert!(world.seen.borrow().iter().any(|r| r.method == "PUT"));
                assert_eq!(
                    sync::run(&a, &st, UID, Mode::Sync).unwrap(),
                    Report::Downloaded
                );
            }
        }

        #[test]
        fn only_the_two_encrypted_files_are_uploaded() {
            let world = World::new(false);
            let a = device();
            let Unlocked { mut vault, .. } = session::unlock(&a, MASTER, None, FAST).unwrap();
            vault.upsert(login("My Bank Login"));
            vault.save_remote(&a).unwrap();
            let st = store(&world, &token("a"));
            sync::run(&a, &st, UID, Mode::Sync).unwrap();

            let uploads = world.uploads();
            assert_eq!(uploads.len(), 2);
            let names: Vec<&str> = uploads
                .iter()
                .map(|r| r.url.rsplit('/').next().unwrap())
                .collect();
            assert_eq!(names, ["keyslot.skvk", Object::Archive.file_name()]);
            // Exactly the bytes the device holds, which start with the formats' magic numbers.
            assert_eq!(uploads[0].body, a.get(Object::KeySlot).unwrap().unwrap());
            assert_eq!(uploads[1].body, a.get(Object::Archive).unwrap().unwrap());
            assert!(uploads[0].body.starts_with(b"SKVK"));
            assert!(uploads[1].body.starts_with(b"SKIM"));
            // No plaintext anywhere in anything that was sent: bodies, URLs or headers.
            for req in world.seen.borrow().iter() {
                let mut all = req.body.clone();
                all.extend_from_slice(req.url.as_bytes());
                for (k, v) in &req.headers {
                    all.extend_from_slice(k.as_bytes());
                    all.extend_from_slice(v.as_bytes());
                }
                for secret in [
                    MASTER,
                    LOGIN_PASSWORD,
                    "My Bank Login",
                    "alice@example.com",
                    "bank.example.com",
                    "purple elephant",
                    "vault.json",
                    "\"entries\"",
                ] {
                    assert!(!contains(&all, secret), "{secret} was sent");
                }
            }
        }

        #[test]
        fn a_refused_upload_changes_nothing_on_either_side() {
            let world = World::new(false);
            world.deny_writes.set(true);
            let a = device();
            let Unlocked { mut vault, .. } = session::unlock(&a, MASTER, None, FAST).unwrap();
            vault.upsert(login("Bank"));
            vault.save_remote(&a).unwrap();
            let before = (
                a.get(Object::KeySlot).unwrap(),
                a.get(Object::Archive).unwrap(),
            );

            let st = store(&world, &token("a"));
            assert!(matches!(
                sync::run(&a, &st, UID, Mode::Sync),
                Err(Error::Remote(_))
            ));
            assert!(world.objects.borrow().is_empty());
            assert_eq!(
                before,
                (
                    a.get(Object::KeySlot).unwrap(),
                    a.get(Object::Archive).unwrap()
                )
            );
            // The vault still opens from this device's own copy.
            assert!(session::unlock(&a, MASTER, None, FAST).is_ok());
            // And it was never linked to the account, so the next sync starts from scratch.
            assert_eq!(a.linked_uid(), None);
        }

        #[test]
        fn a_token_that_belongs_to_somebody_else_sends_nothing_and_changes_nothing() {
            let world = World::new(false);
            let a = device();
            let Unlocked { mut vault, .. } = session::unlock(&a, MASTER, None, FAST).unwrap();
            vault.upsert(login("Bank"));
            vault.save_remote(&a).unwrap();
            let before = (
                a.get(Object::KeySlot).unwrap(),
                a.get(Object::Archive).unwrap(),
            );
            let st = store(&world, &jwt(serde_json::json!({ "sub": "someone-else" })));
            assert_eq!(
                sync::run(&a, &st, UID, Mode::Sync).err(),
                Some(Error::SignedOut)
            );
            assert!(world.seen.borrow().is_empty());
            assert_eq!(
                before,
                (
                    a.get(Object::KeySlot).unwrap(),
                    a.get(Object::Archive).unwrap()
                )
            );
        }
    }
}
