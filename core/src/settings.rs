//! Preferences kept next to the vault in `settings.json`. They hold nothing secret: generator
//! options and whether new logins get a generated password.
use crate::error::Error;
use crate::generator::GenOptions;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::Path;

const FILE: &str = "settings.json";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub generator: GenOptions,
    /// Put a generated password into the form when a new login is started.
    pub auto_generate: bool,
    /// Let screenshots, screen recording and the recent-apps preview show Silk (off by default).
    pub allow_screenshots: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            generator: GenOptions::default(),
            auto_generate: true,
            allow_screenshots: false,
        }
    }
}

impl Settings {
    /// Missing or unreadable files give the defaults.
    pub fn load(dir: &Path) -> Settings {
        let parsed: Option<Settings> = fs::read(dir.join(FILE))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok());
        match parsed {
            Some(s) => Settings {
                generator: s.generator.normalized(),
                auto_generate: s.auto_generate,
                allow_screenshots: s.allow_screenshots,
            },
            None => Settings::default(),
        }
    }

    pub fn save(&self, dir: &Path) -> Result<(), Error> {
        fs::create_dir_all(dir)?;
        let path = dir.join(FILE);
        let tmp = path.with_extension("tmp");
        let body = serde_json::to_vec_pretty(self).map_err(|_| Error::Corrupt)?;
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&body)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::new_id;

    fn temp_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("silk-settings-{}", new_id()))
    }

    #[test]
    fn defaults_when_missing_or_broken() {
        let dir = temp_dir();
        assert_eq!(Settings::load(&dir), Settings::default());
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(FILE), b"{ not json").unwrap();
        assert_eq!(Settings::load(&dir), Settings::default());
    }

    #[test]
    fn saves_and_loads() {
        let dir = temp_dir();
        let mut s = Settings::default();
        s.generator.length = 32;
        s.generator.symbols = false;
        s.auto_generate = false;
        s.allow_screenshots = true;
        s.save(&dir).unwrap();
        assert_eq!(Settings::load(&dir), s);
    }

    #[test]
    fn partial_files_and_out_of_range_values_are_repaired() {
        let dir = temp_dir();
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(FILE), br#"{"generator":{"length":9999,"lower":false,"upper":false,"digits":false,"symbols":false}}"#).unwrap();
        let s = Settings::load(&dir);
        assert_eq!(s.generator.length, crate::generator::MAX_LEN);
        assert!(s.generator.lower);
        assert!(s.auto_generate);
    }
}
