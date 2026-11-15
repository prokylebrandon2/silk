//! Decides what to fill. The Android glue flattens the form into JSON; this module finds the
//! username and password fields, picks matching logins and answers with JSON.
use crate::entry::Entry;
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
struct Request {
    #[serde(default)]
    pkg: String,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    nodes: Vec<Node>,
}

/// An autofillable text field, in on-screen order.
#[derive(Deserialize)]
struct Node {
    #[serde(default)]
    hints: Vec<String>,
    /// Android `InputType` bit field.
    #[serde(default)]
    input: i64,
    /// HTML `type` attribute for web forms.
    #[serde(default)]
    html: Option<String>,
    /// HTML `autocomplete` attribute for web forms (can hold several words).
    #[serde(default)]
    ac: String,
    /// The view's id name, hint and description, and a web field's name, id and placeholder, joined by spaces.
    #[serde(default)]
    label: String,
}

const TYPE_MASK_CLASS: i64 = 0xf;
const TYPE_MASK_VARIATION: i64 = 0xff0;
const TYPE_CLASS_TEXT: i64 = 0x1;
const VARIATION_PASSWORD: i64 = 0x80;
const VARIATION_VISIBLE_PASSWORD: i64 = 0x90;
const VARIATION_WEB_PASSWORD: i64 = 0xe0;
const VARIATION_EMAIL: i64 = 0x20;
const VARIATION_WEB_EMAIL: i64 = 0xd0;

/// Whether the field's `autocomplete` attribute names one of these.
fn ac_has(n: &Node, names: &[&str]) -> bool {
    n.ac.split_whitespace()
        .any(|t| names.iter().any(|x| t.eq_ignore_ascii_case(x)))
}

/// Whether the field's label mentions one of these words.
fn label_has(n: &Node, words: &[&str]) -> bool {
    let l = n.label.to_lowercase();
    words.iter().any(|w| l.contains(w))
}

/// Index of the username field (hinted, or the last text field before the password) and of the password field.
fn detect(nodes: &[Node]) -> (Option<usize>, Option<usize>) {
    let (mut user, mut pass, mut last_text) = (None, None, None);
    for (i, n) in nodes.iter().enumerate() {
        let is_text = (n.input & TYPE_MASK_CLASS) == TYPE_CLASS_TEXT;
        let variation = n.input & TYPE_MASK_VARIATION;
        if ac_has(n, &["new-password"]) || n.hints.iter().any(|h| h == "newPassword") {
            continue; // choosing a new password: not a login to fill
        }
        let is_pass = n.hints.iter().any(|h| h == "password")
            || ac_has(n, &["current-password"])
            || n.html.as_deref() == Some("password")
            || (is_text
                && (variation == VARIATION_PASSWORD
                    || variation == VARIATION_VISIBLE_PASSWORD
                    || variation == VARIATION_WEB_PASSWORD
                    || label_has(n, &["password", "passwd", "pwd"])));
        let is_user = n.hints.iter().any(|h| {
            matches!(
                h.as_str(),
                "username" | "emailAddress" | "phone" | "phoneNumber"
            )
        }) || ac_has(n, &["username", "email", "tel"])
            || n.html.as_deref() == Some("email")
            || (is_text && (variation == VARIATION_EMAIL || variation == VARIATION_WEB_EMAIL))
            || (pass.is_none()
                && !label_has(n, &["search"])
                && label_has(n, &["user", "email", "e-mail", "login", "account"]));
        if is_pass {
            if pass.is_none() {
                pass = Some(i);
                if user.is_none() {
                    user = last_text;
                }
            }
        } else if is_user {
            if user.is_none() {
                user = Some(i);
            }
        } else {
            last_text = Some(i);
        }
    }
    (user, pass)
}

/// A login matches when its URL's host is the page's domain or a parent of it,
/// or when it is `androidapp://<package>` for the app asking.
pub fn url_matches(entry_url: &str, pkg: &str, domain: Option<&str>) -> bool {
    let u = entry_url.trim().to_lowercase();
    if let Some(app) = u.strip_prefix("androidapp://") {
        return !app.is_empty() && app == pkg.to_lowercase();
    }
    let rest = u.split_once("://").map(|x| x.1).unwrap_or(&u);
    let host = rest
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");
    let host = host.strip_prefix("www.").unwrap_or(host);
    let Some(domain) = domain else { return false };
    let domain = domain.to_lowercase();
    let domain = domain.strip_prefix("www.").unwrap_or(&domain);
    !host.is_empty() && (domain == host || domain.ends_with(&format!(".{host}")))
}

/// `entries` is `None` while the vault is locked.
///
/// Answers `{"state":"none"}` (nothing to fill), `{"state":"locked","user":i,"pass":i}` or
/// `{"state":"ok","user":i,"pass":i,"items":[{"label","user","pass"}]}`.
pub fn handle(request: &str, entries: Option<&[Entry]>) -> String {
    let Ok(req) = serde_json::from_str::<Request>(request) else {
        return json!({ "state": "none" }).to_string();
    };
    let (user, pass) = detect(&req.nodes);
    if user.is_none() && pass.is_none() {
        return json!({ "state": "none" }).to_string();
    }
    let Some(entries) = entries else {
        return json!({ "state": "locked", "user": user, "pass": pass }).to_string();
    };
    let items: Vec<serde_json::Value> = entries
        .iter()
        .filter(|e| url_matches(&e.url, &req.pkg, req.domain.as_deref()))
        .map(|e| {
            let label = if e.username.is_empty() {
                e.title.clone()
            } else {
                format!("{} ({})", e.title, e.username)
            };
            json!({ "label": label, "user": e.username, "pass": e.password })
        })
        .collect();
    json!({ "state": "ok", "user": user, "pass": pass, "items": items }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(title: &str, user: &str, url: &str) -> Entry {
        Entry {
            id: title.into(),
            title: title.into(),
            username: user.into(),
            password: "secret".into(),
            url: url.into(),
            otp: String::new(),
            notes: String::new(),
            ..Default::default()
        }
    }

    fn form(json_nodes: &str) -> String {
        format!(r#"{{"pkg":"com.android.chrome","domain":"github.com","nodes":{json_nodes}}}"#)
    }

    #[test]
    fn finds_password_by_input_type_and_username_before_it() {
        // text field (inputType 1) then a password field (1 | 0x80)
        let r = handle(&form(r#"[{"input":1},{"input":129}]"#), None);
        let v: serde_json::Value = serde_json::from_str(&r).unwrap();
        assert_eq!(v["state"], "locked");
        assert_eq!(v["user"], 0);
        assert_eq!(v["pass"], 1);
    }

    #[test]
    fn finds_fields_by_hints_and_html_type() {
        let r = handle(
            &form(r#"[{"hints":["emailAddress"]},{"html":"password"}]"#),
            None,
        );
        let v: serde_json::Value = serde_json::from_str(&r).unwrap();
        assert_eq!((v["user"].as_u64(), v["pass"].as_u64()), (Some(0), Some(1)));
    }

    #[test]
    fn ignores_forms_without_login_fields() {
        let r = handle(&form(r#"[{"input":1}]"#), Some(&[]));
        assert_eq!(r, r#"{"state":"none"}"#);
        assert_eq!(handle("not json", None), r#"{"state":"none"}"#);
    }

    #[test]
    fn fills_only_matching_logins() {
        let entries = [
            entry("GitHub", "me", "https://github.com/login"),
            entry("Other", "you", "https://example.com"),
            entry("Lookalike", "x", "https://evilgithub.com"),
        ];
        let r = handle(
            &form(r#"[{"hints":["username"]},{"hints":["password"]}]"#),
            Some(&entries),
        );
        let v: serde_json::Value = serde_json::from_str(&r).unwrap();
        assert_eq!(v["state"], "ok");
        assert_eq!(v["items"].as_array().unwrap().len(), 1);
        assert_eq!(v["items"][0]["label"], "GitHub (me)");
        assert_eq!(v["items"][0]["pass"], "secret");
    }

    #[test]
    fn finds_email_fields_labels_and_skips_new_passwords() {
        let v = |s: &str| {
            serde_json::from_str::<serde_json::Value>(&handle(&form(s), None)).unwrap()
        };
        // web email variation, then a plain text field whose id says password
        let r = v(r#"[{"input":209},{"input":1,"label":"login_pwd Password"}]"#);
        assert_eq!((r["user"].as_u64(), r["pass"].as_u64()), (Some(0), Some(1)));
        // the email-only first step of a two-step login
        let r = v(r#"[{"html":"email"}]"#);
        assert_eq!((r["user"].as_u64(), r["pass"].as_u64()), (Some(0), None));
        // a new-password field is left alone, current-password is used
        let r = v(
            r#"[{"ac":"username"},{"ac":"new-password","input":129},{"ac":"current-password","input":129}]"#,
        );
        assert_eq!((r["user"].as_u64(), r["pass"].as_u64()), (Some(0), Some(2)));
        let r = v(r#"[{"ac":"username"},{"ac":"new-password","input":129}]"#);
        assert_eq!((r["user"].as_u64(), r["pass"].as_u64()), (Some(0), None));
    }

    #[test]
    fn url_rules() {
        assert!(url_matches("github.com", "x", Some("github.com")));
        assert!(url_matches(
            "https://www.github.com/a?b",
            "x",
            Some("gist.github.com")
        ));
        assert!(url_matches(
            "https://github.com:8443",
            "x",
            Some("www.github.com")
        ));
        assert!(!url_matches(
            "https://github.com",
            "x",
            Some("evilgithub.com")
        ));
        assert!(!url_matches("https://github.com", "x", None));
        assert!(!url_matches("", "x", Some("github.com")));
        assert!(url_matches(
            "androidapp://com.example.app",
            "com.Example.App",
            None
        ));
        assert!(!url_matches(
            "androidapp://com.example.app",
            "com.other",
            Some("example.com")
        ));
    }
}
