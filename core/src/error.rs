use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    NotAVault,
    Corrupt,
    Locked,
    KeyFileRequired,
    KeyFileNotUsed,
    WrongCredentials,
    Crypto,
    Random,
    Io(String),
    /// An import file that can't be read. The message says what to do about it.
    Import(String),
    /// The cloud copy (Supabase) couldn't be reached or refused the request.
    Remote(String),
    /// Supabase refused the account itself (wrong email or password, weak password, ...). The message is shown as it is.
    Account(String),
    /// The saved cloud sign-in is no longer accepted. The user has to sign in again.
    SignedOut,
    /// The vault file is older than one this device has already seen (see `local::DirStore::check_revision`).
    Rollback,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotAVault => f.write_str("This isn't a Silk file."),
            Error::Corrupt => f.write_str("The vault file is damaged."),
            Error::Locked => f.write_str("The vault is locked. Unlock it and try again."),
            Error::KeyFileRequired => f.write_str("This vault needs its key file. Choose it and try again."),
            Error::KeyFileNotUsed => f.write_str("This vault doesn't use a key file. Clear the key file and try again."),
            Error::WrongCredentials => f.write_str("Wrong password or key file. Check both and try again."),
            Error::Crypto => f.write_str("Encryption failed on this device."),
            Error::Random => f.write_str("Couldn't get secure random numbers from the system."),
            Error::Io(e) => write!(f, "Couldn't read or write the vault: {e}"),
            Error::Import(m) => f.write_str(m),
            Error::Remote(e) => write!(f, "Couldn't reach the cloud copy: {e}"),
            Error::Account(m) => f.write_str(m),
            Error::SignedOut => f.write_str("Your cloud sign-in is no longer valid. Sign in again."),
            Error::Rollback => f.write_str(
                "This vault is older than the last copy this device saw, so it wasn't opened. If you meant to go back to an old backup, restore it from the backup option.",
            ),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}
