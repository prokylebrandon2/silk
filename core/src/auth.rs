//! Supabase Auth over HTTPS, as the core sees it (email and password accounts, access tokens),
//! behind a one-method [`Http`] trait.
//!
//! The core never opens a socket. The platform layer implements [`Http`] (on Android, a few lines of
//! Java reached over JNI) and this module does the protocol: building the URLs, the token handling,
//! and turning Supabase's answers into [`Error`]s. That keeps all of it testable on a normal machine.
//!
//! ```text
//! sign up   POST <url>/auth/v1/signup
//! sign in   POST <url>/auth/v1/token?grant_type=password
//! renew     POST <url>/auth/v1/token?grant_type=refresh_token     (refresh token, no password)
//!
//! every call:  apikey: <publishable key>
//! ```
//!
//! The access token that comes back is already a Supabase token (`role: authenticated`, `sub` = the
//! user id), so Supabase Storage (see `supabase`) accepts it as it is: no second identity provider and
//! nothing to set up on a server. The account password is only ever sent to the sign-in and sign-up
//! calls; what is kept afterwards is the refresh token (see `keyfile::Login`).
use crate::error::Error;
use crate::keyfile::Login;
use crate::supabase::Config;
use serde_json::Value;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// An access token is renewed this many seconds before it runs out.
const SKEW_SECS: u64 = 60;
const DEFAULT_LIFETIME_SECS: u64 = 3600;

// ---- the platform seam ----

#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub method: &'static str,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

pub trait Http {
    /// Sends the request and returns whatever status came back, 4xx and 5xx included.
    /// `Err(Error::Remote(_))` is for "no answer at all" (offline, timeout, blocked host).
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error>;
}

// ---- accounts ----

/// A signed-in account: who it is and the tokens to act as them. Wiped on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Auth {
    pub email: String,
    pub uid: String,
    pub access_token: String,
    pub refresh_token: String,
    /// Unix seconds at which `access_token` stops working.
    pub expires_at: u64,
}

impl Auth {
    /// What gets saved in the key file.
    pub fn login(&self) -> Login {
        Login {
            email: self.email.clone(),
            uid: self.uid.clone(),
            refresh_token: self.refresh_token.clone(),
        }
    }

    fn fresh(&self, now: u64) -> bool {
        self.expires_at > now.saturating_add(SKEW_SECS)
    }
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    SignIn,
    SignUp,
    Refresh,
}

/// Signs in an existing account.
pub fn sign_in(http: &dyn Http, cfg: &Config, email: &str, password: &str) -> Result<Auth, Error> {
    let reply = password_call(http, cfg, Op::SignIn, email, password)?;
    session(&reply, email.trim())?
        .ok_or_else(|| Error::Remote("unexpected sign-in answer".into()))
}

/// Creates an account and signs in to it. When the Supabase project asks new accounts to confirm
/// their email first, no session comes back; the message says what to do.
pub fn sign_up(http: &dyn Http, cfg: &Config, email: &str, password: &str) -> Result<Auth, Error> {
    let reply = password_call(http, cfg, Op::SignUp, email, password)?;
    session(&reply, email.trim())?.ok_or_else(|| {
        Error::Account(
            "Account created. Supabase sent a confirmation email: open the link in it, then tap Sign in."
                .into(),
        )
    })
}

fn password_call(
    http: &dyn Http,
    cfg: &Config,
    op: Op,
    email: &str,
    password: &str,
) -> Result<Vec<u8>, Error> {
    let email = email.trim();
    if email.is_empty() || password.is_empty() {
        return Err(Error::Account(
            "Enter the account email and password.".into(),
        ));
    }
    let url = match op {
        Op::SignUp => format!("{}/auth/v1/signup", cfg.base()),
        _ => format!("{}/auth/v1/token?grant_type=password", cfg.base()),
    };
    let body = serde_json::json!({ "email": email, "password": password });
    let mut req = json_request(cfg, url, &body)?;
    let sent = http.send(&req);
    req.body.zeroize(); // it held the password
    answer(op, sent?)
}

/// Trades a saved refresh token for a fresh access token. `email` is only carried along in case
/// the answer doesn't repeat it. Supabase rotates refresh tokens: the new one in the answer
/// replaces the old, which stops working a few seconds later.
pub fn refresh(
    http: &dyn Http,
    cfg: &Config,
    email: &str,
    refresh_token: &str,
) -> Result<Auth, Error> {
    let url = format!("{}/auth/v1/token?grant_type=refresh_token", cfg.base());
    let body = serde_json::json!({ "refresh_token": refresh_token });
    let mut req = json_request(cfg, url, &body)?;
    let sent = http.send(&req);
    req.body.zeroize();
    let reply = answer(Op::Refresh, sent?)?;
    session(&reply, email)?.ok_or_else(|| Error::Remote("unexpected token answer".into()))
}

fn json_request(cfg: &Config, url: String, body: &Value) -> Result<HttpRequest, Error> {
    Ok(HttpRequest {
        method: "POST",
        url,
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("apikey".into(), cfg.key().to_owned()),
        ],
        body: serde_json::to_vec(body).map_err(|_| Error::Corrupt)?,
    })
}

fn answer(op: Op, resp: HttpResponse) -> Result<Vec<u8>, Error> {
    if resp.status == 200 {
        Ok(resp.body)
    } else {
        Err(api_error(op, resp.status, &resp.body))
    }
}

/// Reads a session out of an answer. `Ok(None)` means the answer was a user without a session, which
/// is what sign-up gives while email confirmation is switched on.
fn session(body: &[u8], fallback_email: &str) -> Result<Option<Auth>, Error> {
    let bad = || Error::Remote("unexpected sign-in answer".into());
    let v: Value = serde_json::from_slice(body).map_err(|_| bad())?;
    let text = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
    let Some(access_token) = text(&v, "access_token").filter(|t| !t.is_empty()) else {
        return Ok(None);
    };
    let refresh_token = text(&v, "refresh_token").filter(|t| !t.is_empty()).ok_or_else(bad)?;
    let user = v.get("user").ok_or_else(bad)?;
    let uid = text(user, "id").ok_or_else(bad)?;
    let email = text(user, "email")
        .filter(|e| !e.is_empty())
        .unwrap_or_else(|| fallback_email.to_owned());
    let lifetime = v
        .get("expires_in")
        .and_then(|n| n.as_u64().or_else(|| n.as_str()?.parse().ok()))
        .unwrap_or(DEFAULT_LIFETIME_SECS);
    Ok(Some(Auth {
        email,
        uid,
        access_token,
        refresh_token,
        expires_at: unix_now().saturating_add(lifetime),
    }))
}

/// A short, single-line piece of the server's own message, for the error text.
fn clean(msg: &str) -> String {
    msg.chars().filter(|c| !c.is_control()).take(160).collect()
}

/// Supabase Auth's error body is `{"code":400,"error_code":"invalid_credentials","msg":"..."}`; older
/// shapes use `{"error":"invalid_grant","error_description":"..."}`. The code names the problem.
fn api_error(op: Op, status: u16, body: &[u8]) -> Error {
    let v: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let field = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("");
    let code = field("error_code");
    let legacy = field("error");
    let msg = ["msg", "message", "error_description"]
        .iter()
        .map(|k| field(k))
        .find(|m| !m.is_empty())
        .unwrap_or(legacy);
    let lower = msg.to_ascii_lowercase();
    let account = |m: &str| Error::Account(m.to_owned());
    let wrong = || account("Wrong email or password.");
    let too_many = || account("Too many attempts. Wait a few minutes and try again.");
    let unconfirmed = || {
        account("Confirm your email first: open the link Supabase sent to that address, then sign in.")
    };
    let exists = || account("That email already has an account. Use Sign in instead.");

    match code {
        "invalid_credentials" => return wrong(),
        "email_not_confirmed" => return unconfirmed(),
        "user_already_exists" | "email_exists" => return exists(),
        "weak_password" => {
            return if msg.is_empty() {
                account("Choose a stronger account password.")
            } else {
                account(&clean(msg))
            }
        }
        "validation_failed" | "email_address_invalid" => {
            return account("That email address isn't valid.")
        }
        "signup_disabled" => return account("Sign-ups are turned off in the Supabase project."),
        "email_provider_disabled" => {
            return account("Email sign-in is turned off in the Supabase project.")
        }
        "over_request_rate_limit" | "over_email_send_rate_limit" => return too_many(),
        "user_banned" => return account("This account has been disabled."),
        // The saved sign-in is no good any more: the user signs in again.
        "refresh_token_not_found"
        | "refresh_token_already_used"
        | "session_expired"
        | "session_not_found"
        | "user_not_found"
        | "bad_jwt" => return Error::SignedOut,
        _ => {}
    }
    // Older answers, and answers from in front of Auth, carry no error_code.
    if status == 429 {
        return too_many();
    }
    if legacy == "invalid_grant" {
        return if op == Op::Refresh { Error::SignedOut } else { wrong() };
    }
    if lower.contains("invalid login credentials") {
        return wrong();
    }
    if lower.contains("email not confirmed") {
        return unconfirmed();
    }
    if lower.contains("already registered") {
        return exists();
    }
    if lower.contains("refresh token") && op == Op::Refresh {
        return Error::SignedOut;
    }
    if lower.contains("api key") || lower.contains("apikey") {
        return account("The Supabase key built into this app isn't accepted.");
    }
    if msg.is_empty() {
        Error::Remote(format!("Supabase Auth answered {status}"))
    } else {
        Error::Remote(format!("Supabase Auth answered {status}: {}", clean(msg)))
    }
}

// ---- the signed-in account ----

/// A signed-in account's tokens, kept fresh: the access token is renewed when it has run out, or when
/// the service that received it rejected it ([`Account::renew`]). Whatever talks to Supabase on the
/// account's behalf (Storage) gets its token here.
pub struct Account<'a> {
    http: &'a dyn Http,
    cfg: Config,
    auth: Mutex<Auth>,
}

impl<'a> Account<'a> {
    pub fn new(http: &'a dyn Http, cfg: Config, auth: Auth) -> Result<Account<'a>, Error> {
        // The uid becomes part of the object path, so it must be what Supabase hands out (a UUID):
        // letters, digits, - and _.
        let ok = !auth.uid.is_empty()
            && auth
                .uid
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        if !ok {
            return Err(Error::Corrupt);
        }
        Ok(Account {
            http,
            cfg,
            auth: Mutex::new(auth),
        })
    }

    /// The current tokens. The refresh token can change during a sync, so callers read it back afterwards.
    pub fn auth(&self) -> Auth {
        self.lock().clone()
    }

    pub fn uid(&self) -> String {
        self.lock().uid.clone()
    }

    fn lock(&self) -> MutexGuard<'_, Auth> {
        self.auth.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// An access token that is good for at least another minute: the current one, or a renewed one.
    pub fn token(&self) -> Result<Zeroizing<String>, Error> {
        let (fresh, token) = {
            let a = self.lock();
            (a.fresh(unix_now()), a.access_token.clone())
        };
        if fresh {
            Ok(Zeroizing::new(token))
        } else {
            self.renew()
        }
    }

    /// Trades the refresh token for a new access token, whatever the clock says. Used after a service
    /// rejected the current one.
    pub fn renew(&self) -> Result<Zeroizing<String>, Error> {
        let (email, refresh_token) = {
            let a = self.lock();
            (a.email.clone(), a.refresh_token.clone())
        };
        let next = refresh(self.http, &self.cfg, &email, &refresh_token)?;
        let token = Zeroizing::new(next.access_token.clone());
        *self.lock() = next;
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    /// Answers with the scripted responses in order and remembers what it was asked.
    struct Script {
        replies: RefCell<VecDeque<HttpResponse>>,
        seen: RefCell<Vec<HttpRequest>>,
    }

    impl Script {
        fn new(replies: Vec<(u16, &str)>) -> Script {
            Script {
                replies: RefCell::new(
                    replies
                        .into_iter()
                        .map(|(status, body)| HttpResponse {
                            status,
                            body: body.as_bytes().to_vec(),
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

    const URL: &str = "https://abcdefghijklmnopqrst.supabase.co";

    fn cfg() -> Config {
        Config::new(URL, "sb_publishable_testkey").unwrap()
    }

    fn auth(expires_at: u64) -> Auth {
        Auth {
            email: "me@example.com".into(),
            uid: "uid123".into(),
            access_token: "at1".into(),
            refresh_token: "rt1".into(),
            expires_at,
        }
    }

    const SESSION_OK: &str = r#"{"access_token":"tok","token_type":"bearer","expires_in":3600,"expires_at":1,"refresh_token":"ref","user":{"id":"uid123","email":"me@example.com"}}"#;
    const REFRESH_OK: &str = r#"{"access_token":"tok2","token_type":"bearer","expires_in":3600,"refresh_token":"ref2","user":{"id":"uid123","email":"me@example.com"}}"#;
    const DEAD_REFRESH: &str = r#"{"code":400,"error_code":"refresh_token_not_found","msg":"Invalid Refresh Token: Refresh Token Not Found"}"#;

    fn header<'a>(req: &'a HttpRequest, name: &str) -> Option<&'a str> {
        req.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn sign_in_reads_the_tokens_and_the_password_goes_only_to_the_sign_in_url() {
        let http = Script::new(vec![(200, SESSION_OK)]);
        let a = sign_in(&http, &cfg(), " me@example.com ", "hunter22").unwrap();
        assert_eq!(
            (
                a.uid.as_str(),
                a.access_token.as_str(),
                a.refresh_token.as_str()
            ),
            ("uid123", "tok", "ref")
        );
        // The lifetime comes from expires_in, not from the server's clock.
        assert!(a.expires_at > unix_now() + 3000);
        let seen = http.seen.borrow();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].method, "POST");
        assert_eq!(seen[0].url, format!("{URL}/auth/v1/token?grant_type=password"));
        assert_eq!(header(&seen[0], "apikey"), Some("sb_publishable_testkey"));
        assert!(String::from_utf8_lossy(&seen[0].body).contains("\"email\":\"me@example.com\""));
        assert_eq!(a.login().refresh_token, "ref");
    }

    #[test]
    fn sign_up_uses_its_own_url_and_handles_a_project_that_wants_email_confirmation() {
        let http = Script::new(vec![(200, SESSION_OK)]);
        let a = sign_up(&http, &cfg(), "me@example.com", "hunter22").unwrap();
        assert_eq!(a.uid, "uid123");
        assert_eq!(http.seen.borrow()[0].url, format!("{URL}/auth/v1/signup"));

        // With confirmation switched on the answer is a user and no session: nothing to sign in with yet.
        let pending = Script::new(vec![(
            200,
            r#"{"id":"uid123","email":"me@example.com","confirmation_sent_at":"2026-11-08T00:00:00Z"}"#,
        )]);
        match sign_up(&pending, &cfg(), "me@example.com", "hunter22") {
            Err(Error::Account(m)) => assert!(m.contains("confirmation email"), "{m}"),
            other => panic!("{:?}", other.err()),
        }
        // The same answer to a sign-in is not a session either.
        let odd = Script::new(vec![(200, r#"{"id":"uid123"}"#)]);
        assert!(matches!(
            sign_in(&odd, &cfg(), "me@example.com", "x").err(),
            Some(Error::Remote(_))
        ));
    }

    #[test]
    fn expires_in_may_be_a_number_a_string_or_missing() {
        for (body, min) in [
            (r#""expires_in":7200,"#, 7000),
            (r#""expires_in":"7200","#, 7000),
            ("", 3000),
        ] {
            let json = format!(
                r#"{{"access_token":"t",{body}"refresh_token":"r","user":{{"id":"u1"}}}}"#
            );
            let http = Script::new(vec![(200, json.as_str())]);
            let a = sign_in(&http, &cfg(), "me@example.com", "x").unwrap();
            assert!(a.expires_at > unix_now() + min, "{json}");
            // No email in the answer: the one that was typed is kept.
            assert_eq!(a.email, "me@example.com");
        }
    }

    #[test]
    fn supabase_errors_become_readable_messages() {
        let account = |s: &str| Error::Account(s.to_owned());
        let wrong = Script::new(vec![(
            400,
            r#"{"code":400,"error_code":"invalid_credentials","msg":"Invalid login credentials"}"#,
        )]);
        assert_eq!(
            sign_in(&wrong, &cfg(), "a@b.c", "x").err(),
            Some(account("Wrong email or password."))
        );
        // The older shape without error_code.
        let legacy = Script::new(vec![(
            400,
            r#"{"error":"invalid_grant","error_description":"Invalid login credentials"}"#,
        )]);
        assert_eq!(
            sign_in(&legacy, &cfg(), "a@b.c", "x").err(),
            Some(account("Wrong email or password."))
        );

        let exists = Script::new(vec![(
            422,
            r#"{"code":422,"error_code":"user_already_exists","msg":"User already registered"}"#,
        )]);
        assert!(matches!(
            sign_up(&exists, &cfg(), "a@b.c", "password1").err(),
            Some(Error::Account(m)) if m.contains("Use Sign in")
        ));

        let weak = Script::new(vec![(
            422,
            r#"{"code":422,"error_code":"weak_password","msg":"Password should be at least 6 characters."}"#,
        )]);
        assert!(matches!(
            sign_up(&weak, &cfg(), "a@b.c", "123").err(),
            Some(Error::Account(m)) if m.contains("6 characters")
        ));

        let unconfirmed = Script::new(vec![(
            400,
            r#"{"code":400,"error_code":"email_not_confirmed","msg":"Email not confirmed"}"#,
        )]);
        assert!(matches!(
            sign_in(&unconfirmed, &cfg(), "a@b.c", "x").err(),
            Some(Error::Account(m)) if m.contains("Confirm your email")
        ));

        let limited = Script::new(vec![(
            429,
            r#"{"code":429,"error_code":"over_request_rate_limit","msg":"Request rate limit reached"}"#,
        )]);
        assert!(matches!(
            sign_in(&limited, &cfg(), "a@b.c", "x").err(),
            Some(Error::Account(m)) if m.contains("Too many")
        ));

        let key = Script::new(vec![(401, r#"{"message":"Invalid API key","hint":"x"}"#)]);
        assert!(matches!(
            sign_in(&key, &cfg(), "a@b.c", "x").err(),
            Some(Error::Account(m)) if m.contains("key built into this app")
        ));

        // Anything else is a server problem, not an account problem.
        let odd = Script::new(vec![(500, "oops")]);
        assert!(matches!(
            sign_in(&odd, &cfg(), "a@b.c", "x").err(),
            Some(Error::Remote(_))
        ));

        // No request at all when a field is empty.
        let none = Script::new(vec![]);
        assert!(matches!(
            sign_in(&none, &cfg(), "", "x").err(),
            Some(Error::Account(_))
        ));
        assert!(none.seen.borrow().is_empty());
    }

    #[test]
    fn a_dead_refresh_token_means_signed_out_but_a_server_error_does_not() {
        let http = Script::new(vec![(400, DEAD_REFRESH)]);
        assert_eq!(
            refresh(&http, &cfg(), "me@example.com", "old").err(),
            Some(Error::SignedOut)
        );
        let used = Script::new(vec![(
            400,
            r#"{"code":400,"error_code":"refresh_token_already_used","msg":"Invalid Refresh Token: Already Used"}"#,
        )]);
        assert_eq!(
            refresh(&used, &cfg(), "me@example.com", "old").err(),
            Some(Error::SignedOut)
        );
        let legacy = Script::new(vec![(
            400,
            r#"{"error":"invalid_grant","error_description":"Invalid Refresh Token: Refresh Token Not Found"}"#,
        )]);
        assert_eq!(
            refresh(&legacy, &cfg(), "me@example.com", "old").err(),
            Some(Error::SignedOut)
        );
        // Being offline or a 5xx must never sign the user out.
        let down = Script::new(vec![(503, "upstream unavailable")]);
        assert!(matches!(
            refresh(&down, &cfg(), "me@example.com", "old").err(),
            Some(Error::Remote(_))
        ));

        let ok = Script::new(vec![(200, REFRESH_OK)]);
        let a = refresh(&ok, &cfg(), "me@example.com", "a b+c\"d").unwrap();
        assert_eq!(
            (a.email.as_str(), a.uid.as_str(), a.refresh_token.as_str()),
            ("me@example.com", "uid123", "ref2")
        );
        let seen = ok.seen.borrow();
        assert_eq!(
            seen[0].url,
            format!("{URL}/auth/v1/token?grant_type=refresh_token")
        );
        // JSON, so the token needs no URL encoding and quotes in it can't break the body.
        let body: Value = serde_json::from_slice(&seen[0].body).unwrap();
        assert_eq!(body["refresh_token"], "a b+c\"d");
    }

    #[test]
    fn an_expired_token_is_renewed_on_demand_and_the_new_refresh_token_is_kept() {
        // Expired: token() trades the refresh token first.
        let http = Script::new(vec![(200, REFRESH_OK)]);
        let account = Account::new(&http, cfg(), auth(0)).unwrap();
        assert_eq!(account.token().unwrap().as_str(), "tok2");
        assert_eq!(account.auth().refresh_token, "ref2");
        assert_eq!(account.uid(), "uid123");

        // Fresh: no request at all.
        let http = Script::new(vec![]);
        let account = Account::new(&http, cfg(), auth(unix_now() + 3600)).unwrap();
        assert_eq!(account.token().unwrap().as_str(), "at1");
        assert!(http.seen.borrow().is_empty());

        // renew() ignores the clock: it is for a token the other side rejected.
        let http = Script::new(vec![(200, REFRESH_OK)]);
        let account = Account::new(&http, cfg(), auth(unix_now() + 3600)).unwrap();
        assert_eq!(account.renew().unwrap().as_str(), "tok2");

        // A dead refresh token means signed out.
        let http = Script::new(vec![(400, DEAD_REFRESH)]);
        let account = Account::new(&http, cfg(), auth(0)).unwrap();
        assert_eq!(account.token().err(), Some(Error::SignedOut));
    }

    #[test]
    fn the_uid_is_checked_before_it_can_reach_a_path() {
        let http = Script::new(vec![]);
        for bad in ["../other", "a/b", "", "a b", "x?y=1"] {
            let mut a = auth(0);
            a.uid = bad.into();
            assert!(Account::new(&http, cfg(), a).is_err(), "{bad}");
        }
    }
}
