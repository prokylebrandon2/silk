//! Moving logins in and out as plain files: Proton Pass exports (JSON and CSV) and any CSV with
//! the usual login columns. The files this module reads and writes are NOT encrypted; the caller
//! decides where they go and tells the user.
//!
//! Proton Pass JSON: `{"vaults": {id: {"name", "items": [{"data": {"type", "metadata": {"name", "note"},
//! "content": {...}}, "state"}]}}}`. Proton Pass CSV: `type,name,url,email,username,password,note,totp,createTime,modifyTime,vault`.
use crate::entry::{new_id, Entry};
use crate::error::Error;
use serde_json::{json, Value};

/// What an import found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Imported {
    pub entries: Vec<Entry>,
    /// Items left out: in the trash, empty or not readable.
    pub skipped: usize,
    /// Passkeys on imported logins. They can't be copied to another app, so they are dropped.
    pub passkeys: usize,
}

fn bad(msg: &str) -> Error {
    Error::Import(msg.to_string())
}

/// Reads a Proton Pass JSON or CSV export (or a generic login CSV).
pub fn import(data: &[u8]) -> Result<Imported, Error> {
    if data.starts_with(b"PK") {
        return Err(bad(
            "This is a .zip file. Unzip it and choose the Data.json inside.",
        ));
    }
    let text = std::str::from_utf8(data)
        .map_err(|_| bad("This file isn't text. Choose a JSON or CSV export."))?;
    let text = text.trim_start_matches('\u{feff}');
    let head = text.trim_start();
    if head.starts_with("-----BEGIN PGP") {
        return Err(bad(
            "This export is encrypted. In Proton Pass export again without encryption.",
        ));
    }
    if head.starts_with('{') {
        import_json(head)
    } else {
        import_csv(text)
    }
}

// ---------------------------------------------------------------- shared helpers

/// A trimmed string field, or "".
fn text(v: Option<&Value>) -> String {
    v.and_then(Value::as_str).unwrap_or("").trim().to_string()
}

/// A string field exactly as stored (passwords and notes keep their whitespace).
fn raw(v: Option<&Value>) -> String {
    v.and_then(Value::as_str).unwrap_or("").to_string()
}

fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map(|x| x.1).unwrap_or(url);
    rest.split('/').next().unwrap_or("").to_string()
}

fn append_lines(notes: &mut String, lines: Vec<String>) {
    for l in lines {
        if !notes.is_empty() {
            notes.push('\n');
        }
        notes.push_str(&l);
    }
}

/// "cardholderName" -> "Cardholder name".
fn humanize(key: &str) -> String {
    let mut out = String::new();
    for (i, c) in key.chars().enumerate() {
        if i == 0 {
            out.extend(c.to_uppercase());
        } else if c.is_uppercase() {
            out.push(' ');
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// The simple text and number fields of a Proton item that isn't a login (cards, identities), as note lines.
fn flatten(content: Option<&Value>) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(obj) = content.and_then(Value::as_object) {
        for (k, v) in obj {
            let t = match v {
                Value::String(s) => s.trim().to_string(),
                Value::Number(n) => n.to_string(),
                _ => continue,
            };
            if !t.is_empty() {
                lines.push(format!("{}: {}", humanize(k), t));
            }
        }
    }
    lines
}

fn extra_fields(data: &Value) -> Vec<String> {
    let Some(list) = data.get("extraFields").and_then(Value::as_array) else {
        return Vec::new();
    };
    list.iter()
        .filter_map(|f| {
            let name = f.get("fieldName")?.as_str()?.trim();
            let d = f.get("data")?;
            let val = d
                .get("content")
                .or_else(|| d.get("totpUri"))?
                .as_str()?
                .trim();
            if name.is_empty() || val.is_empty() {
                None
            } else {
                Some(format!("{name}: {val}"))
            }
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn make_login(
    title: &str,
    email: &str,
    username: &str,
    password: &str,
    urls: &[String],
    totp: &str,
    note: &str,
) -> Entry {
    let (email, username) = (email.trim(), username.trim());
    let login = if email.is_empty() { username } else { email };
    let mut extra: Vec<String> = Vec::new();
    if !email.is_empty() && !username.is_empty() && !email.eq_ignore_ascii_case(username) {
        extra.push(format!("Username: {username}"));
    }
    if urls.len() > 1 {
        extra.push(format!("Other websites: {}", urls[1..].join(", ")));
    }
    let url = urls.first().cloned().unwrap_or_default();
    let title = title.trim();
    let title = if !title.is_empty() {
        title.to_string()
    } else if !url.is_empty() {
        host_of(&url)
    } else if !login.is_empty() {
        login.to_string()
    } else {
        "Untitled".to_string()
    };
    let mut notes = note.to_string();
    append_lines(&mut notes, extra);
    Entry {
        id: new_id(),
        title,
        username: login.to_string(),
        password: password.to_string(),
        url,
        otp: totp.trim().to_string(),
        notes,
        ..Default::default()
    }
}

// ---------------------------------------------------------------- JSON import

fn import_json(text: &str) -> Result<Imported, Error> {
    let root: Value =
        serde_json::from_str(text).map_err(|_| bad("That JSON file couldn't be read."))?;
    if root.get("encrypted").and_then(Value::as_bool) == Some(true) {
        return Err(bad(
            "This export is encrypted. In Proton Pass export again without encryption.",
        ));
    }
    let vaults = root
        .get("vaults")
        .and_then(Value::as_object)
        .ok_or_else(|| bad("This doesn't look like a Proton Pass export."))?;
    let mut out = Imported::default();
    for vault in vaults.values() {
        let Some(items) = vault.get("items").and_then(Value::as_array) else {
            continue;
        };
        for item in items {
            match json_item(item, &mut out.passkeys) {
                Some(e) => out.entries.push(e),
                None => out.skipped += 1,
            }
        }
    }
    Ok(out)
}

fn json_item(item: &Value, passkeys: &mut usize) -> Option<Entry> {
    if item.get("state").and_then(Value::as_i64) == Some(2) {
        return None; // in the trash
    }
    let data = item.get("data")?;
    let meta = data.get("metadata")?;
    let kind = data.get("type").and_then(Value::as_str).unwrap_or("");
    let content = data.get("content");
    let title = text(meta.get("name"));
    let note = raw(meta.get("note"));
    let extras = extra_fields(data);

    if kind == "login" {
        let c = content?;
        let urls: Vec<String> = c
            .get("urls")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(|u| u.trim().to_string())
                    .filter(|u| !u.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        let email = text(c.get("itemEmail"));
        let mut user = text(c.get("itemUsername"));
        if user.is_empty() && email.is_empty() {
            user = text(c.get("username")); // older exports
        }
        if let Some(n) = c.get("passkeys").and_then(Value::as_array).map(Vec::len) {
            *passkeys += n;
        }
        let mut e = make_login(
            &title,
            &email,
            &user,
            &raw(c.get("password")),
            &urls,
            &text(c.get("totpUri")),
            &note,
        );
        append_lines(&mut e.notes, extras);
        return Some(e);
    }

    // Notes, aliases, cards, identities: kept as an entry whose notes hold the fields.
    let mut lines = flatten(content);
    lines.extend(extras);
    let username = if kind == "alias" {
        text(item.get("aliasEmail"))
    } else {
        String::new()
    };
    if title.is_empty() && note.trim().is_empty() && lines.is_empty() && username.is_empty() {
        return None;
    }
    let title = if title.is_empty() {
        humanize(if kind.is_empty() { "item" } else { kind })
    } else {
        title
    };
    let mut e = Entry {
        id: new_id(),
        title,
        username,
        notes: note,
        ..Default::default()
    };
    append_lines(&mut e.notes, lines);
    Some(e)
}

// ---------------------------------------------------------------- CSV

/// RFC 4180: quoted fields, doubled quotes, commas and line breaks inside quotes, CRLF or LF.
fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if quoted {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    quoted = false;
                }
            } else {
                field.push(c);
            }
        } else {
            match c {
                '"' if field.is_empty() => quoted = true,
                ',' => row.push(std::mem::take(&mut field)),
                '\r' => {}
                '\n' => {
                    row.push(std::mem::take(&mut field));
                    rows.push(std::mem::take(&mut row));
                }
                _ => field.push(c),
            }
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

fn find_col(header: &[String], names: &[&str]) -> Option<usize> {
    names
        .iter()
        .find_map(|n| header.iter().position(|h| h == n))
}

fn import_csv(text: &str) -> Result<Imported, Error> {
    let mut rows = parse_csv(text)
        .into_iter()
        .filter(|r| !r.iter().all(|c| c.trim().is_empty()));
    let header: Vec<String> = rows
        .next()
        .ok_or_else(|| bad("That file is empty."))?
        .iter()
        .map(|h| h.trim().to_lowercase())
        .collect();
    let c_title = find_col(&header, &["name", "title"]);
    let c_url = find_col(
        &header,
        &["url", "login_uri", "website", "login url", "uri"],
    );
    let c_email = find_col(&header, &["email"]);
    let c_user = find_col(&header, &["username", "login_username", "user name"]);
    let c_pass = find_col(&header, &["password", "login_password"]);
    let c_note = find_col(&header, &["note", "notes", "extra"]);
    let c_totp = find_col(&header, &["totp", "login_totp", "otp"]);
    if c_title.is_none()
        && c_url.is_none()
        && c_user.is_none()
        && c_pass.is_none()
        && c_email.is_none()
    {
        return Err(bad(
            "Couldn't find login columns (name, url, username, password) in this CSV.",
        ));
    }
    let mut out = Imported::default();
    for row in rows {
        let get = |i: Option<usize>| i.and_then(|i| row.get(i)).map(String::as_str).unwrap_or("");
        let urls: Vec<String> = get(c_url).split_whitespace().map(String::from).collect();
        let e = make_login(
            get(c_title),
            get(c_email),
            get(c_user),
            get(c_pass),
            &urls,
            get(c_totp),
            get(c_note),
        );
        out.entries.push(e);
    }
    Ok(out)
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

// ---------------------------------------------------------------- export

fn pct_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The one-time-password field as an otpauth:// link, which is what Proton Pass stores.
fn otp_uri(e: &Entry) -> String {
    let o = e.otp.trim();
    if o.is_empty() {
        return String::new();
    }
    if o.to_ascii_lowercase().starts_with("otpauth://") {
        return o.to_string();
    }
    let secret: String = o
        .chars()
        .filter(|c| !matches!(c, ' ' | '-' | '='))
        .collect::<String>()
        .to_uppercase();
    if secret.is_empty() {
        return String::new();
    }
    let label = if e.title.is_empty() {
        "Silk"
    } else {
        e.title.as_str()
    };
    format!(
        "otpauth://totp/{}?secret={}&algorithm=SHA1&digits=6&period=30",
        pct_encode(label),
        secret
    )
}

fn is_note(e: &Entry) -> bool {
    e.password.is_empty()
        && e.username.is_empty()
        && e.url.trim().is_empty()
        && e.otp.trim().is_empty()
}

/// The note column of an export. Cards, identities and other items keep their labelled fields as
/// lines of the note, since neither file format has a place for them.
fn export_note(e: &Entry) -> String {
    let mut note = e.notes.clone();
    let lines = e
        .fields
        .iter()
        .filter(|f| !f.value.is_empty())
        .map(|f| format!("{}: {}", f.label, f.value))
        .collect();
    append_lines(&mut note, lines);
    note
}

/// Proton Pass splits the login into an email and a username column.
fn split_login(username: &str) -> (&str, &str) {
    if username.contains('@') {
        (username, "")
    } else {
        ("", username)
    }
}

/// CSV in Proton Pass's own column layout. `now` is a Unix time in seconds.
pub fn export_csv(entries: &[Entry], now: u64) -> String {
    let mut out = String::from(
        "type,name,url,email,username,password,note,totp,createTime,modifyTime,vault\n",
    );
    for e in entries {
        if e.kind == "folder" {
            continue;
        }
        let (email, user) = split_login(&e.username);
        let cols = [
            (if is_note(e) { "note" } else { "login" }).to_string(),
            e.title.clone(),
            e.url.clone(),
            email.to_string(),
            user.to_string(),
            e.password.clone(),
            export_note(e),
            otp_uri(e),
            now.to_string(),
            now.to_string(),
            "Silk".to_string(),
        ];
        let line: Vec<String> = cols.iter().map(|c| csv_field(c)).collect();
        out.push_str(&line.join(","));
        out.push('\n');
    }
    out
}

/// JSON in the shape of a Proton Pass export. `now` is a Unix time in seconds.
pub fn export_json(entries: &[Entry], now: u64) -> String {
    let share = new_id();
    let items: Vec<Value> = entries
        .iter()
        .filter(|e| e.kind != "folder")
        .map(|e| {
            let (email, user) = split_login(&e.username);
            let note = is_note(e);
            let kind = if note { "note" } else { "login" };
            let urls: Vec<String> = if e.url.trim().is_empty() {
                Vec::new()
            } else {
                vec![e.url.trim().to_string()]
            };
            let content = if note {
                json!({})
            } else {
                json!({
                    "itemEmail": email,
                    "itemUsername": user,
                    "password": e.password,
                    "urls": urls,
                    "totpUri": otp_uri(e),
                    "passkeys": Vec::<String>::new(),
                })
            };
            json!({
                "itemId": new_id(),
                "shareId": share,
                "data": {
                    "metadata": { "name": e.title, "note": export_note(e), "itemUuid": new_id() },
                    "extraFields": Vec::<String>::new(),
                    "type": kind,
                    "content": content,
                },
                "state": 1,
                "aliasEmail": Value::Null,
                "contentFormatVersion": 1,
                "createTime": now,
                "modifyTime": now,
                "pinned": false,
            })
        })
        .collect();
    let mut vaults = serde_json::Map::new();
    vaults.insert(
        share.clone(),
        json!({ "name": "Silk", "description": "Exported from Silk", "items": items }),
    );
    let root = json!({
        "version": "1.0.0",
        "userId": "silk",
        "encrypted": false,
        "vaults": vaults,
    });
    serde_json::to_string_pretty(&root).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROTON_JSON: &str = r#"{
      "version": "1.20.0", "userId": "u", "encrypted": false,
      "vaults": {
        "v1": {
          "name": "Personal", "description": "",
          "items": [
            {"itemId":"1","shareId":"v1","state":1,"aliasEmail":null,
             "data":{"type":"login","metadata":{"name":"GitHub","note":"work account"},
               "extraFields":[{"fieldName":"Recovery","type":"text","data":{"content":"abc"}}],
               "content":{"itemEmail":"me@example.com","itemUsername":"me","password":" s3cret ",
                 "urls":["https://github.com","https://gist.github.com"],
                 "totpUri":"otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
                 "passkeys":[{"keyId":"x"}]}}},
            {"itemId":"2","shareId":"v1","state":1,
             "data":{"type":"note","metadata":{"name":"Wi-Fi","note":"code 1234"},"extraFields":[],"content":{}}},
            {"itemId":"3","shareId":"v1","state":1,
             "data":{"type":"creditCard","metadata":{"name":"Visa","note":""},"extraFields":[],
               "content":{"cardholderName":"A B","number":"4111111111111111","verificationNumber":"123","expirationDate":"2030-01","pin":""}}},
            {"itemId":"4","shareId":"v1","state":1,"aliasEmail":"x.y@passmail.net",
             "data":{"type":"alias","metadata":{"name":"Shop alias","note":""},"extraFields":[],"content":{}}},
            {"itemId":"5","shareId":"v1","state":2,
             "data":{"type":"login","metadata":{"name":"Trashed","note":""},"extraFields":[],"content":{"itemEmail":"","itemUsername":"t","password":"p","urls":[],"totpUri":"","passkeys":[]}}},
            {"itemId":"6","shareId":"v1","state":1,
             "data":{"type":"login","metadata":{"name":"Old format","note":""},"extraFields":[],"content":{"username":"olduser","password":"pw","urls":["example.org"],"totpUri":""}}}
          ]
        }
      }
    }"#;

    #[test]
    fn imports_proton_json() {
        let imp = import(PROTON_JSON.as_bytes()).unwrap();
        assert_eq!(imp.skipped, 1); // the trashed one
        assert_eq!(imp.passkeys, 1);
        assert_eq!(imp.entries.len(), 5);

        let gh = imp.entries.iter().find(|e| e.title == "GitHub").unwrap();
        assert_eq!(gh.username, "me@example.com");
        assert_eq!(gh.password, " s3cret ");
        assert_eq!(gh.url, "https://github.com");
        assert!(gh.otp.starts_with("otpauth://totp/GitHub"));
        assert!(gh.notes.starts_with("work account"));
        assert!(gh.notes.contains("Username: me"));
        assert!(gh.notes.contains("Other websites: https://gist.github.com"));
        assert!(gh.notes.contains("Recovery: abc"));

        let note = imp.entries.iter().find(|e| e.title == "Wi-Fi").unwrap();
        assert_eq!(note.notes, "code 1234");
        assert!(note.password.is_empty());

        let card = imp.entries.iter().find(|e| e.title == "Visa").unwrap();
        assert!(card.notes.contains("Number: 4111111111111111"));
        assert!(card.notes.contains("Cardholder name: A B"));
        assert!(!card.notes.contains("Pin"));

        let alias = imp
            .entries
            .iter()
            .find(|e| e.title == "Shop alias")
            .unwrap();
        assert_eq!(alias.username, "x.y@passmail.net");

        let old = imp
            .entries
            .iter()
            .find(|e| e.title == "Old format")
            .unwrap();
        assert_eq!(old.username, "olduser");
        assert_eq!(old.url, "example.org");
    }

    #[test]
    fn imports_proton_csv_with_quotes_and_newlines() {
        let csv = "type,name,url,email,username,password,note,totp,createTime,modifyTime,vault\r\n\
                   login,\"Acme, Inc\",https://acme.test,me@acme.test,,\"p\"\"w,1\",\"line one\nline two\",JBSWY3DPEHPK3PXP,1,2,Personal\r\n\
                   \r\n\
                   note,Memo,,,,,remember,,1,2,Personal\r\n";
        let imp = import(csv.as_bytes()).unwrap();
        assert_eq!(imp.entries.len(), 2);
        let a = &imp.entries[0];
        assert_eq!(a.title, "Acme, Inc");
        assert_eq!(a.username, "me@acme.test");
        assert_eq!(a.password, "p\"w,1");
        assert_eq!(a.notes, "line one\nline two");
        assert_eq!(a.otp, "JBSWY3DPEHPK3PXP");
        assert_eq!(imp.entries[1].title, "Memo");
        assert_eq!(imp.entries[1].notes, "remember");
    }

    #[test]
    fn accepts_other_managers_column_names_and_a_bom() {
        let csv = "\u{feff}name,url,username,password,note\nSite,https://s.test,bob,pw,hi\n";
        let imp = import(csv.as_bytes()).unwrap();
        assert_eq!(imp.entries[0].username, "bob");
        let bw = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n,,login,Bw,,,0,https://b.test,al,pw2,SECRET\n";
        let imp = import(bw.as_bytes()).unwrap();
        assert_eq!(
            (
                imp.entries[0].title.as_str(),
                imp.entries[0].url.as_str(),
                imp.entries[0].otp.as_str()
            ),
            ("Bw", "https://b.test", "SECRET")
        );
    }

    #[test]
    fn explains_files_it_cannot_read() {
        assert!(matches!(import(b"PK\x03\x04rest"), Err(Error::Import(m)) if m.contains("zip")));
        assert!(
            matches!(import(b"-----BEGIN PGP MESSAGE-----\nabc"), Err(Error::Import(m)) if m.contains("encrypted"))
        );
        assert!(
            matches!(import(br#"{"encrypted":true,"vaults":{}}"#), Err(Error::Import(m)) if m.contains("encrypted"))
        );
        assert!(matches!(import(br#"{"hello":1}"#), Err(Error::Import(_))));
        assert!(matches!(import(b"a,b,c\n1,2,3\n"), Err(Error::Import(_))));
        assert!(matches!(import(&[0xff, 0xfe, 0x00]), Err(Error::Import(_))));
        assert!(matches!(import(b""), Err(Error::Import(_))));
    }

    fn sample() -> Vec<Entry> {
        vec![
            Entry {
                id: "1".into(),
                title: "Acme, \"Inc\"".into(),
                username: "me@acme.test".into(),
                password: "p\"w,1".into(),
                url: "https://acme.test".into(),
                otp: "JBSW Y3DP-EHPK 3PXP".into(),
                notes: "a\nb".into(),
                ..Default::default()
            },
            Entry {
                id: "2".into(),
                title: "Plain".into(),
                username: "bob".into(),
                password: "x".into(),
                ..Default::default()
            },
            Entry {
                id: "3".into(),
                title: "Memo".into(),
                notes: "just a note".into(),
                ..Default::default()
            },
        ]
    }

    fn same(a: &Entry, b: &Entry) -> bool {
        a.title == b.title
            && a.username == b.username
            && a.password == b.password
            && a.url == b.url
            && a.notes == b.notes
    }

    #[test]
    fn csv_export_round_trips_and_uses_protons_columns() {
        let csv = export_csv(&sample(), 1_700_000_000);
        assert!(csv.starts_with(
            "type,name,url,email,username,password,note,totp,createTime,modifyTime,vault\n"
        ));
        assert!(csv.contains("login,\"Acme, \"\"Inc\"\"\",https://acme.test,me@acme.test,,"));
        assert!(csv.contains("otpauth://totp/Acme%2C%20%22Inc%22?secret=JBSWY3DPEHPK3PXP"));
        assert!(csv.contains("\nnote,Memo,"));
        let back = import(csv.as_bytes()).unwrap();
        assert_eq!(back.entries.len(), 3);
        for (a, b) in sample().iter().zip(back.entries.iter()) {
            assert!(same(a, b), "{a:?} vs {b:?}");
        }
        assert!(crate::otp::parse(&back.entries[0].otp).is_some());
    }

    #[test]
    fn json_export_round_trips() {
        let json = export_json(&sample(), 1_700_000_000);
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["encrypted"], false);
        let back = import(json.as_bytes()).unwrap();
        assert_eq!(back.entries.len(), 3);
        for (a, b) in sample().iter().zip(back.entries.iter()) {
            assert!(same(a, b), "{a:?} vs {b:?}");
        }
        assert!(back.entries[2].password.is_empty());
        assert_eq!(back.skipped, 0);
    }

    #[test]
    fn csv_parser_edge_cases() {
        assert_eq!(
            parse_csv("a,b\n"),
            vec![vec!["a".to_string(), "b".to_string()]]
        );
        assert_eq!(
            parse_csv("\"x\"\"y\",\"\"\n"),
            vec![vec!["x\"y".to_string(), String::new()]]
        );
        assert_eq!(
            parse_csv("a,b"),
            vec![vec!["a".to_string(), "b".to_string()]]
        );
        assert!(parse_csv("").is_empty());
    }
}
