use std::ffi::NulError;
use std::fmt::{Debug, Display, Formatter};
use std::option::Option::None;
use std::str::Utf8Error;

#[derive(Debug, Clone)]
pub enum Error {
    Message(String),
    Utf8Error(Utf8Error),
    NulError(NulError),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<Utf8Error> for Error {
    fn from(err: Utf8Error) -> Self {
        Self::Utf8Error(err)
    }
}

impl From<NulError> for Error {
    fn from(err: NulError) -> Self {
        Self::NulError(err)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Message(_) => None,
            Error::Utf8Error(err) => Some(err),
            Error::NulError(err) => Some(err),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Message(msg) => Display::fmt(msg, f),
            Error::Utf8Error(err) => Display::fmt(err, f),
            Error::NulError(err) => Display::fmt(err, f),
        }
    }
}
