//! One saved login, and the random ids that name them.
use crate::generator::random_bytes;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// One saved item: a login unless `kind` says otherwise.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub struct Entry {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub otp: String,
    #[serde(default)]
    pub notes: String,
    /// "login" (or empty), "card", "note", "identity", "password", "other" or "folder".
    #[serde(default)]
    pub kind: String,
    /// The id of the folder this item is in, or empty.
    #[serde(default)]
    pub folder: String,
    /// The labelled values of a card, an identity or an other item.
    #[serde(default)]
    pub fields: Vec<Field>,
}

/// One labelled value on a card, an identity or an other item.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub struct Field {
    pub label: String,
    #[serde(default)]
    pub value: String,
    /// Kept hidden until the user taps Show (card number, security code, PIN, hidden custom fields).
    #[serde(default)]
    pub secret: bool,
}

/// The kinds of item, in the order the app numbers them.
pub const KINDS: [&str; 7] = [
    "login", "card", "note", "identity", "password", "other", "folder",
];

/// The fields a new card or identity starts with. Every other kind starts with none.
pub fn template(kind: &str) -> Vec<Field> {
    let field = |label: &str, secret: bool| Field {
        label: label.to_string(),
        value: String::new(),
        secret,
    };
    match kind {
        "card" => vec![
            field("Cardholder name", false),
            field("Card number", true),
            field("Expiry date", false),
            field("Security code", true),
            field("PIN", true),
        ],
        "identity" => [
            "Full name",
            "Email",
            "Phone",
            "Address",
            "City",
            "State or region",
            "Postal code",
            "Country",
        ]
        .iter()
        .map(|label| field(label, false))
        .collect(),
        _ => Vec::new(),
    }
}

impl Entry {
    /// Which of [`KINDS`] this is. A missing or unknown kind is a login.
    pub fn kind_index(&self) -> usize {
        KINDS.iter().position(|k| *k == self.kind).unwrap_or(0)
    }

    /// The value of the field with this label, or empty.
    pub fn field(&self, label: &str) -> &str {
        self.fields
            .iter()
            .find(|f| f.label == label)
            .map(|f| f.value.as_str())
            .unwrap_or("")
    }

    /// The second line of this item in the list: what tells it apart from the others of its kind.
    pub fn subtitle(&self) -> String {
        match self.kind_index() {
            0 => self.username.clone(),
            1 => {
                let digits: Vec<char> = self
                    .field("Card number")
                    .chars()
                    .filter(char::is_ascii_digit)
                    .collect();
                if digits.len() < 4 {
                    return String::new();
                }
                let last: String = digits[digits.len() - 4..].iter().collect();
                format!("\u{2022}\u{2022}\u{2022}\u{2022} {last}")
            }
            2 => self.notes.lines().next().unwrap_or("").trim().to_string(),
            3 => match self.field("Full name") {
                "" => self.field("Email").to_string(),
                name => name.to_string(),
            },
            _ => String::new(),
        }
    }
}

/// A random 128-bit id as lowercase hex.
pub fn new_id() -> String {
    random_bytes(16)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_32_hex_characters_and_differ() {
        let a = new_id();
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, new_id());
    }

    #[test]
    fn kinds_and_list_subtitles() {
        assert_eq!(Entry::default().kind_index(), 0);
        let card = Entry {
            kind: "card".into(),
            fields: vec![Field {
                label: "Card number".into(),
                value: "4111 1111 1111 1234".into(),
                secret: true,
            }],
            ..Default::default()
        };
        assert_eq!(card.kind_index(), 1);
        assert_eq!(card.subtitle(), "\u{2022}\u{2022}\u{2022}\u{2022} 1234");
        let note = Entry {
            kind: "note".into(),
            notes: "first\nsecond".into(),
            ..Default::default()
        };
        assert_eq!(note.subtitle(), "first");
        assert_eq!(template("card").len(), 5);
        assert!(template("other").is_empty());
    }

    #[test]
    fn a_vault_from_before_kinds_still_loads() {
        let e: Entry =
            serde_json::from_str(r#"{"id":"1","title":"Mail","username":"me"}"#).unwrap();
        assert_eq!(e.kind_index(), 0);
        assert!(e.fields.is_empty() && e.folder.is_empty());
    }
}
