//! A configurable password generator: length, character sets and look-alike removal.
//! Every selected set is guaranteed to appear at least once; the rest is uniform over the pool.
use serde::{Deserialize, Serialize};

pub const MIN_LEN: usize = 8;
pub const MAX_LEN: usize = 64;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*-_=+?";
/// Characters that are easy to misread: l I 1 and O 0 o.
const LOOKALIKES: &str = "Il1O0o";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GenOptions {
    pub length: usize,
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_lookalikes: bool,
}

impl Default for GenOptions {
    fn default() -> Self {
        GenOptions {
            length: 20,
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
            avoid_lookalikes: true,
        }
    }
}

impl GenOptions {
    /// Length forced into range and at least one character set switched on.
    pub fn normalized(&self) -> GenOptions {
        let mut o = self.clone();
        o.length = o.length.clamp(MIN_LEN, MAX_LEN);
        if !(o.lower || o.upper || o.digits || o.symbols) {
            o.lower = true;
        }
        o
    }

    /// The character sets that are switched on, each as a list of characters.
    fn classes(&self) -> Vec<Vec<char>> {
        let mut sets: Vec<&str> = Vec::new();
        if self.lower {
            sets.push(LOWER);
        }
        if self.upper {
            sets.push(UPPER);
        }
        if self.digits {
            sets.push(DIGITS);
        }
        if self.symbols {
            sets.push(SYMBOLS);
        }
        sets.into_iter()
            .map(|s| {
                s.chars()
                    .filter(|c| !(self.avoid_lookalikes && LOOKALIKES.contains(*c)))
                    .collect::<Vec<char>>()
            })
            .filter(|v| !v.is_empty())
            .collect()
    }

    /// Number of distinct characters the generator draws from.
    pub fn pool_size(&self) -> usize {
        self.normalized().classes().iter().map(|c| c.len()).sum()
    }

    /// A rough strength figure: length x log2(pool size).
    pub fn entropy_bits(&self) -> f64 {
        let o = self.normalized();
        o.length as f64 * (o.pool_size() as f64).log2()
    }
}

/// `n` random bytes from the operating system.
pub(crate) fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    getrandom::getrandom(&mut v).expect("the OS random number generator failed");
    v
}

/// Uniform random number below `n` (n > 0), without modulo bias.
fn below(n: usize) -> usize {
    let n = n as u32;
    let limit = u32::MAX - (u32::MAX % n);
    loop {
        let r = random_bytes(4);
        let v = u32::from_le_bytes([r[0], r[1], r[2], r[3]]);
        if v < limit {
            return (v % n) as usize;
        }
    }
}

pub fn generate(options: &GenOptions) -> String {
    let o = options.normalized();
    let classes = o.classes();
    let pool: Vec<char> = classes.iter().flatten().copied().collect();
    let mut out: Vec<char> = Vec::with_capacity(o.length);
    for class in &classes {
        out.push(class[below(class.len())]);
    }
    while out.len() < o.length {
        out.push(pool[below(pool.len())]);
    }
    // Fisher-Yates, so the guaranteed characters don't sit at the front.
    for i in (1..out.len()).rev() {
        let j = below(i + 1);
        out.swap(i, j);
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_is_clamped_and_respected() {
        let mut o = GenOptions {
            length: 3,
            ..GenOptions::default()
        };
        assert_eq!(generate(&o).chars().count(), MIN_LEN);
        o.length = 500;
        assert_eq!(generate(&o).chars().count(), MAX_LEN);
        o.length = 33;
        assert_eq!(generate(&o).chars().count(), 33);
    }

    #[test]
    fn every_selected_set_appears() {
        let o = GenOptions {
            length: 8,
            ..GenOptions::default()
        };
        for _ in 0..200 {
            let p = generate(&o);
            assert!(p.chars().any(|c| c.is_ascii_lowercase()), "{p}");
            assert!(p.chars().any(|c| c.is_ascii_uppercase()), "{p}");
            assert!(p.chars().any(|c| c.is_ascii_digit()), "{p}");
            assert!(p.chars().any(|c| SYMBOLS.contains(c)), "{p}");
        }
    }

    #[test]
    fn only_the_selected_sets_are_used() {
        let o = GenOptions {
            length: 40,
            lower: false,
            upper: false,
            digits: true,
            symbols: false,
            avoid_lookalikes: false,
        };
        assert!(generate(&o).chars().all(|c| c.is_ascii_digit()));
        let o = GenOptions {
            length: 40,
            lower: true,
            upper: false,
            digits: false,
            symbols: false,
            avoid_lookalikes: false,
        };
        assert!(generate(&o).chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn lookalikes_can_be_excluded() {
        let o = GenOptions {
            length: 64,
            ..GenOptions::default()
        };
        for _ in 0..100 {
            assert!(!generate(&o).chars().any(|c| LOOKALIKES.contains(c)));
        }
    }

    #[test]
    fn no_sets_falls_back_to_lowercase() {
        let o = GenOptions {
            length: 12,
            lower: false,
            upper: false,
            digits: false,
            symbols: false,
            avoid_lookalikes: true,
        };
        assert!(o.normalized().lower);
        assert!(generate(&o).chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn passwords_differ_and_entropy_grows_with_length() {
        let o = GenOptions::default();
        assert_ne!(generate(&o), generate(&o));
        let longer = GenOptions {
            length: 30,
            ..o.clone()
        };
        assert!(longer.entropy_bits() > o.entropy_bits());
        assert!(o.pool_size() > 50);
    }
}
