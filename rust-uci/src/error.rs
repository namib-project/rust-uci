// Copyright 2021, Benjamin Ludewig
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::ffi::NulError;
use std::fmt::Debug;
use std::str::Utf8Error;

use thiserror::Error;

#[derive(Debug, Clone, Error, PartialEq)]
pub enum Error {
    #[error("{0}")]
    Message(String),
    #[error("{0}")]
    Utf8Error(#[from] Utf8Error),
    #[error("{0}")]
    NulError(#[from] NulError),
    /// uci was unable to find the entry for `entry_identifier`, e.g. during `uci.get()`
    #[error("Entry not found: {entry_identifier}")]
    EntryNotFound { entry_identifier: String },
}

pub type Result<T> = std::result::Result<T, Error>;
