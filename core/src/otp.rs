//! RFC 6238 time-based one-time passwords, plus Base32 and `otpauth://` parsing.
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algo {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OtpParams {
    pub secret: Vec<u8>,
    pub digits: u32,
    pub period: u64,
    pub algo: Algo,
}

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Decodes RFC 4648 Base32, ignoring case, spaces, dashes and `=` padding.
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for c in s.chars() {
        if c == ' ' || c == '-' || c == '=' {
            continue;
        }
        let c = c.to_ascii_uppercase();
        let v = ALPHABET.iter().position(|&a| a as char == c)? as u32;
        buffer = ((buffer << 5) | v) & 0xFFFF;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xFF) as u8);
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Accepts a bare Base32 secret or an `otpauth://totp/...` link. Returns `None` if it can't be read.
pub fn parse(input: &str) -> Option<OtpParams> {
    let s = input.trim();
    if s.is_empty() {
        return None;
    }
    if !s.to_ascii_lowercase().starts_with("otpauth://") {
        return base32_decode(s).map(|secret| OtpParams {
            secret,
            digits: 6,
            period: 30,
            algo: Algo::Sha1,
        });
    }
    let query = s.split_once('?')?.1;
    let q: HashMap<String, String> = query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (pct_decode(k).to_ascii_lowercase(), pct_decode(v)))
        .collect();
    let secret = base32_decode(q.get("secret")?)?;
    let algo = match q
        .get("algorithm")
        .map(|a| a.to_ascii_uppercase())
        .as_deref()
    {
        Some("SHA256") => Algo::Sha256,
        Some("SHA512") => Algo::Sha512,
        _ => Algo::Sha1,
    };
    let digits = q
        .get("digits")
        .and_then(|d| d.parse::<u32>().ok())
        .unwrap_or(6)
        .clamp(6, 8);
    let period = q
        .get("period")
        .and_then(|p| p.parse::<u64>().ok())
        .unwrap_or(30)
        .max(1);
    Some(OtpParams {
        secret,
        digits,
        period,
        algo,
    })
}

/// A name for the Add authenticator screen, read from an `otpauth://` link: its `issuer`, else the part of
/// the label before the colon, else the whole label. `None` for anything else, or when the link names nothing.
pub fn issuer(input: &str) -> Option<String> {
    let s = input.trim();
    if !s.to_ascii_lowercase().starts_with("otpauth://") {
        return None;
    }
    let rest = &s["otpauth://".len()..];
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let from_query = query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| pct_decode(k).eq_ignore_ascii_case("issuer"))
        .map(|(_, v)| pct_decode(v));
    let label = pct_decode(path.split_once('/').map_or("", |(_, l)| l));
    let from_label = match label.split_once(':') {
        Some((who, _)) => who.to_string(),
        None => label.clone(),
    };
    [from_query, Some(from_label)]
        .into_iter()
        .flatten()
        .map(|n| n.trim().to_string())
        .find(|n| !n.is_empty())
}

macro_rules! hmac_tag {
    ($digest:ty, $key:expr, $msg:expr) => {{
        let mut m =
            <Hmac<$digest> as Mac>::new_from_slice($key).expect("HMAC accepts any key length");
        m.update($msg);
        m.finalize().into_bytes().to_vec()
    }};
}

/// The code for the 30-second (or `period`) window containing `unix_secs`.
pub fn code(p: &OtpParams, unix_secs: u64) -> String {
    let counter = (unix_secs / p.period).to_be_bytes();
    let tag: Vec<u8> = match p.algo {
        Algo::Sha1 => hmac_tag!(Sha1, &p.secret, &counter),
        Algo::Sha256 => hmac_tag!(Sha256, &p.secret, &counter),
        Algo::Sha512 => hmac_tag!(Sha512, &p.secret, &counter),
    };
    let o = (tag[tag.len() - 1] & 0x0f) as usize;
    let bin = ((u32::from(tag[o]) & 0x7f) << 24)
        | (u32::from(tag[o + 1]) << 16)
        | (u32::from(tag[o + 2]) << 8)
        | u32::from(tag[o + 3]);
    let digits = p.digits.clamp(1, 9);
    let modulus = 10u32.pow(digits);
    format!("{:0width$}", bin % modulus, width = digits as usize)
}

pub fn seconds_left(p: &OtpParams, unix_secs: u64) -> u64 {
    p.period - (unix_secs % p.period)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rfc(secret: &[u8], algo: Algo) -> OtpParams {
        OtpParams {
            secret: secret.to_vec(),
            digits: 8,
            period: 30,
            algo,
        }
    }

    #[test]
    fn sha1_matches_rfc6238_vectors() {
        let p = rfc(b"12345678901234567890", Algo::Sha1);
        assert_eq!(code(&p, 59), "94287082");
        assert_eq!(code(&p, 1_111_111_109), "07081804");
        assert_eq!(code(&p, 1_111_111_111), "14050471");
        assert_eq!(code(&p, 1_234_567_890), "89005924");
        assert_eq!(code(&p, 2_000_000_000), "69279037");
        assert_eq!(code(&p, 20_000_000_000), "65353130");
    }

    #[test]
    fn sha256_and_sha512_match_rfc6238_vectors() {
        assert_eq!(
            code(&rfc(b"12345678901234567890123456789012", Algo::Sha256), 59),
            "46119246"
        );
        let key512 = b"1234567890123456789012345678901234567890123456789012345678901234";
        assert_eq!(code(&rfc(key512, Algo::Sha512), 59), "90693936");
    }

    #[test]
    fn six_digit_codes_are_the_tail_of_the_eight_digit_code() {
        let p = OtpParams {
            secret: b"12345678901234567890".to_vec(),
            digits: 6,
            period: 30,
            algo: Algo::Sha1,
        };
        assert_eq!(code(&p, 59), "287082");
    }

    #[test]
    fn base32_decodes_with_padding_spaces_and_lowercase() {
        assert_eq!(base32_decode("JBSWY3DPEE======").unwrap(), b"Hello!");
        assert_eq!(base32_decode("jbsw y3dp-ee").unwrap(), b"Hello!");
        assert_eq!(
            base32_decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap(),
            b"12345678901234567890"
        );
        assert!(base32_decode("not base32 !!").is_none());
        assert!(base32_decode("").is_none());
    }

    #[test]
    fn parses_otpauth_links() {
        let p = parse("otpauth://totp/Acme%20Co:bob?secret=JBSWY3DPEHPK3PXP&digits=8&period=60&algorithm=sha256").unwrap();
        assert_eq!((p.digits, p.period, p.algo), (8, 60, Algo::Sha256));
        let d = parse("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!((d.digits, d.period, d.algo), (6, 30, Algo::Sha1));
        assert!(parse("otpauth://totp/x?issuer=y").is_none());
        assert!(parse("   ").is_none());
    }

    #[test]
    fn names_an_otpauth_link() {
        let secret = "secret=JBSWY3DPEHPK3PXP";
        let named = |link: String| issuer(&link);
        assert_eq!(
            named(format!(
                "otpauth://totp/Acme%20Co:bob@x.com?{secret}&issuer=Other"
            ))
            .as_deref(),
            Some("Other")
        );
        assert_eq!(
            named(format!("otpauth://totp/Acme%20Co:bob@x.com?{secret}")).as_deref(),
            Some("Acme Co")
        );
        assert_eq!(
            named(format!("otpauth://totp/GitHub%3Abob?{secret}")).as_deref(),
            Some("GitHub")
        );
        assert_eq!(
            named(format!("otpauth://totp/bob@example.com?{secret}")).as_deref(),
            Some("bob@example.com")
        );
        assert_eq!(named(format!("otpauth://totp/?{secret}")), None);
        assert_eq!(named("JBSWY3DPEHPK3PXP".to_string()), None);
    }

    #[test]
    fn countdown_never_reaches_zero() {
        let p = rfc(b"x", Algo::Sha1);
        assert_eq!(seconds_left(&p, 60), 30);
        assert_eq!(seconds_left(&p, 89), 1);
    }
}
