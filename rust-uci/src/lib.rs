// Copyright 2021, Benjamin Ludewig
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bindings to OpenWRT UCI
//!
//! This crate provides a safe interface to OpenWRT's Unified Configuration Interface C-Library.
//!
//! # Building
//!
//! Both UCI libraries and headers are required to build this crate. There are multiple options available to locate
//! UCI.
//!
//! ## Inside OpenWRT SDK
//!
//! If building inside the OpenWRT SDK with OpenWRT's UCI package set the environment variable
//! `UCI_DIR=$(STAGING_DIR)/usr` using the corresponding Makefile.
//! rust-uci will automatically use the headers and libraries for the target system.
//!
//! ## Vendored
//!
//! If no `UCI_DIR` variable is set, rust-uci will compile against the distributed libuci source files licensed under GPLv2.
//!
//! # Example Usage
//!
//! ```no_run
//! use rust_uci::Uci;
//!
//! let mut uci = Uci::new().expect("unable to create UCI context");
//! // Get type of a section
//! assert_eq!(uci.get("network.wan").expect("unable to get value for network.wan"), "interface");
//! // Get value of an option, UCI's extended syntax is supported
//! assert_eq!(uci.get("network.@interface[0].proto").expect("unable to get value for network.@interface[0].proto"), "static");
//! assert_eq!(uci.get("network.lan.proto").expect("unable to get value for network.lan.proto"), "static");
//!
//! // Create a new section
//! uci.set("network.newnet", "interface").expect("unable to set network.newnet");
//! uci.set("network.newnet.proto", "static").expect("unable to set network.newnet.proto");
//! uci.set("network.newnet.ifname", "en0").expect("unable to set network.newnet.ifname");
//! uci.set("network.newnet.enabled", "1").expect("unable to set network.newnet.enabled");
//! uci.set("network.newnet.ipaddr", "2.3.4.5").expect("unable to set network.newnet.ipaddr");
//! uci.set("network.newnet.test", "123").expect("unable to set network.newnet.test");
//! // Delete option
//! uci.delete("network.newnet.test").expect("unable to delete network.newnet.test");
//! // IMPORTANT: Commit or revert the changes
//! uci.commit("network").expect("unable to commit changes");
//! uci.revert("network").expect("unable to revert changes");
//!
//! ```

pub mod error;

use core::ptr;
use libuci_sys::{
    uci_alloc_context, uci_commit, uci_context, uci_delete, uci_element, uci_free_context,
    uci_get_errorstr, uci_list, uci_lookup_ptr, uci_option_type_UCI_TYPE_STRING, uci_ptr,
    uci_ptr_UCI_LOOKUP_COMPLETE, uci_revert, uci_save, uci_set, uci_set_confdir, uci_set_savedir,
    uci_type_UCI_TYPE_OPTION, uci_type_UCI_TYPE_SECTION, uci_unload,
};
use log::debug;
use std::sync::Mutex;
use std::{
    ffi::{CStr, CString},
    fmt::Display,
    ops::{Deref, DerefMut},
};

use crate::error::{Error, Result};

#[allow(clippy::cast_possible_wrap)]
const UCI_OK: i32 = libuci_sys::UCI_OK as i32;

// Global lock to ensure that only one instance of libuci function calls is running at the time.
// Necessary because libuci uses thread-unsafe functions with global state (e.g., strtok).
static LIBRARY_LOCK: Mutex<()> = Mutex::new(());

// Ensures that the global library lock is held while evaluating `$call`.
// The second parameter indicates whether a check for reentrancy should be performed, and requires
// `self` to be a mutable borrow of a `Uci` instance.
macro_rules! libuci_locked {
    ($self:ident, $call:expr) => {{
        // Lock global library mutex, if we aren't already holding it in a function call higher up
        // in the stack.
        let libuci_lock_guard = if !$self.lock_held {
            let libuci_lock_guard = Some(
                LIBRARY_LOCK
                    .lock()
                    .expect("global libuci library lock was poisoned."),
            );
            $self.lock_held = true;
            libuci_lock_guard
        } else {
            None
        };
        let result = $call;
        // If we were the ones who locked the global library lock, release it.
        if let Some(libuci_lock_guard) = libuci_lock_guard {
            $self.lock_held = false;
            drop(libuci_lock_guard);
        }
        result
    }};
    ($call:expr) => {{
        let _libuci_lock_guard = Some(
            LIBRARY_LOCK
                .lock()
                .expect("global libuci library lock was poisoned."),
        );
        $call
    }};
}

/// Contains the native `uci_context`
pub struct Uci {
    ctx: *mut uci_context,
    lock_held: bool,
}

/// A `UciValue` obtained from the get method can be either
/// a simple string value or a list which is implemented as a vector of string values
#[derive(Debug, Clone)]
pub enum UciValue {
    String(String),
    List(Vec<String>),
}

impl Display for UciValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UciValue::String(value) => Display::fmt(value, f),
            UciValue::List(list) => {
                write!(f, "{}", list.join(" "))
            }
        }
    }
}

impl Drop for Uci {
    fn drop(&mut self) {
        libuci_locked!(self, unsafe { uci_free_context(self.ctx) })
    }
}

/// Contains the native `uci_ptr` and it's raw `CString` key
/// this is done so the raw `CString` stays alive until the `uci_ptr` is dropped
struct UciPtr(uci_ptr, *mut std::os::raw::c_char);

impl Deref for UciPtr {
    type Target = uci_ptr;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for UciPtr {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for UciPtr {
    fn drop(&mut self) {
        unsafe { CString::from_raw(self.1) };
    }
}

impl Uci {
    /// Creates a new UCI context.
    /// The C memory will be freed when the object is dropped.
    pub fn new() -> Result<Uci> {
        let ctx = libuci_locked!(unsafe { uci_alloc_context() });
        if !ctx.is_null() {
            Ok(Uci {
                ctx,
                lock_held: false,
            })
        } else {
            Err(Error::Message(String::from("Could not alloc uci context")))
        }
    }

    /// Sets the config directory of UCI, this is `/etc/config` by default.
    pub fn set_config_dir(&mut self, config_dir: &str) -> Result<()> {
        libuci_locked!(self, {
            let result = unsafe {
                let raw = CString::new(config_dir)?;
                uci_set_confdir(
                    self.ctx,
                    raw.as_bytes_with_nul()
                        .as_ptr()
                        .cast::<std::os::raw::c_char>(),
                )
            };
            if result == UCI_OK {
                debug!("Set config dir to: {}", config_dir);
                Ok(())
            } else {
                Err(Error::Message(format!(
                    "Cannot set config dir: {}, {}",
                    config_dir,
                    self.get_last_error()
                        .unwrap_or_else(|_| String::from("Unknown"))
                )))
            }
        })
    }

    /// Sets the save directory of UCI, this is `/tmp/.uci` by default.
    pub fn set_save_dir(&mut self, save_dir: &str) -> Result<()> {
        let raw = CString::new(save_dir)?;
        libuci_locked!(self, {
            let result = unsafe {
                uci_set_savedir(
                    self.ctx,
                    raw.as_bytes_with_nul()
                        .as_ptr()
                        .cast::<std::os::raw::c_char>(),
                )
            };
            if result == UCI_OK {
                debug!("Set save dir to: {}", save_dir);
                Ok(())
            } else {
                Err(Error::Message(format!(
                    "Cannot set save dir: {}, {}",
                    save_dir,
                    self.get_last_error()
                        .unwrap_or_else(|_| String::from("Unknown"))
                )))
            }
        })
    }

    /// Delete an option or section in UCI.
    /// UCI will keep the delta changes in a temporary location until `commit()` or `revert()` is called.
    ///
    /// Allowed keys are like `network.wan.proto`, `network.@interface[-1].iface`, `network.wan` and `network.@interface[-1]`
    ///
    /// if the deletion failed an `Err` is returned.
    pub fn delete(&mut self, identifier: &str) -> Result<()> {
        let mut ptr = self.get_ptr(identifier)?;
        libuci_locked!(self, {
            let result = unsafe { uci_delete(self.ctx, &mut ptr.0) };
            if result != UCI_OK {
                return Err(Error::Message(format!(
                    "Could not delete uci key: {}, {}, {}",
                    identifier,
                    result,
                    self.get_last_error()
                        .unwrap_or_else(|_| String::from("Unknown"))
                )));
            }
            let result = unsafe { uci_save(self.ctx, ptr.p) };
            if result == UCI_OK {
                Ok(())
            } else {
                Err(Error::Message(format!(
                    "Could not save uci key: {}, {}, {}",
                    identifier,
                    result,
                    self.get_last_error()
                        .unwrap_or_else(|_| String::from("Unknown"))
                )))
            }
        })
    }

    /// Revert changes to an option, section or package
    ///
    /// Allowed keys are like `network`, `network.wan.proto`, `network.@interface[-1].iface`, `network.wan` and `network.@interface[-1]`
    ///
    /// if the deletion failed an `Err` is returned.
    pub fn revert(&mut self, identifier: &str) -> Result<()> {
        libuci_locked!(self, {
            let mut ptr = self.get_ptr(identifier)?;
            let result = unsafe { uci_revert(self.ctx, &mut ptr.0) };
            if result != UCI_OK {
                return Err(Error::Message(format!(
                    "Could not revert uci key: {}, {}, {}",
                    identifier,
                    result,
                    self.get_last_error()
                        .unwrap_or_else(|_| String::from("Unknown"))
                )));
            }
            let result = unsafe { uci_save(self.ctx, ptr.p) };
            if result == UCI_OK {
                Ok(())
            } else {
                Err(Error::Message(format!(
                    "Could not save uci key: {}, {}, {}",
                    identifier,
                    result,
                    self.get_last_error()
                        .unwrap_or_else(|_| String::from("Unknown"))
                )))
            }
        })
    }

    /// Sets an option value or section type in UCI, creates the key if necessary.
    /// UCI will keep the delta changes in a temporary location until `commit()` or `revert()` is called.
    ///
    /// Allowed keys are like `network.wan.proto`, `network.@interface[-1].iface`, `network.wan` and `network.@interface[-1]`
    ///
    /// if the assignment failed an `Err` is returned.
    pub fn set(&mut self, identifier: &str, val: &str) -> Result<()> {
        if val.contains('\'') {
            return Err(Error::Message(format!(
                "Values may not contain quotes: {}={}",
                identifier, val
            )));
        }
        libuci_locked!(self, {
            let mut ptr = self.get_ptr(format!("{}={}", identifier, val).as_ref())?;
            if ptr.value.is_null() {
                return Err(Error::Message(format!(
                    "parsed value is null: {}={}",
                    identifier, val
                )));
            }
            let result = unsafe { uci_set(self.ctx, &mut ptr.0) };
            if result != UCI_OK {
                return Err(Error::Message(format!(
                    "Could not set uci key: {}={}, {}, {}",
                    identifier,
                    val,
                    result,
                    self.get_last_error()
                        .unwrap_or_else(|_| String::from("Unknown"))
                )));
            }
            let result = unsafe { uci_save(self.ctx, ptr.p) };
            if result == UCI_OK {
                Ok(())
            } else {
                Err(Error::Message(format!(
                    "Could not save uci key: {}={}, {}, {}",
                    identifier,
                    val,
                    result,
                    self.get_last_error()
                        .unwrap_or_else(|_| String::from("Unknown"))
                )))
            }
        })
    }

    /// Commit all changes to the specified package
    /// writing the temporary delta to the config file
    pub fn commit(&mut self, package: &str) -> Result<()> {
        libuci_locked!(self, {
            let mut ptr = self.get_ptr(package)?;
            let result = unsafe { uci_commit(self.ctx, &mut ptr.p, false) };
            if result != UCI_OK {
                return Err(Error::Message(format!(
                    "Could not set commit uci package: {}, {}, {}",
                    package,
                    result,
                    self.get_last_error()
                        .unwrap_or_else(|_| String::from("Unknown"))
                )));
            }
            if !ptr.p.is_null() {
                unsafe {
                    uci_unload(self.ctx, ptr.p);
                }
            }
            Ok(())
        })
    }

    /// Queries an option value or section type from UCI.
    /// If a key has been changed in the delta, the updated value will be returned.
    ///
    /// Allowed keys are like `network.wan.proto`, `network.@interface[-1].iface`, `network.lan` and `network.@interface[-1]`
    ///
    /// if the entry does not exist an `Err` is returned.
    pub fn get(&mut self, key: &str) -> Result<UciValue> {
        let ptr = libuci_locked!(self, { self.get_ptr(key)? });
        if ptr.flags & uci_ptr_UCI_LOOKUP_COMPLETE == 0 {
            return Err(Error::Message(format!("Lookup failed: {}", key)));
        }
        let last = unsafe { *ptr.last };
        #[allow(non_upper_case_globals)]
        match last.type_ {
            uci_type_UCI_TYPE_OPTION => {
                let opt = unsafe { *ptr.o };
                if opt.section.is_null() {
                    return Err(Error::Message(format!("uci section was null: {}", key)));
                }
                let sect = unsafe { *opt.section };
                if sect.package.is_null() {
                    return Err(Error::Message(format!("uci package was null: {}", key)));
                }
                let pack = unsafe { *sect.package };

                let mut list_str = String::new();
                let value = match opt.type_ {
                    uci_option_type_UCI_TYPE_STRING => {
                        let value = unsafe { String::from(CStr::from_ptr(opt.v.string).to_str()?) };
                        UciValue::String(value)
                    }
                    uci_option_type_UCI_TYPE_LIST => {
                        let mut list = vec![];
                        let mut elem_ptr = unsafe { opt.v.list.next as *const uci_element };
                        let list_ptr = unsafe { &(*elem_ptr).list as *const uci_list };
                        loop {
                            let list_ptr_next = unsafe { (*elem_ptr).list.next as *const uci_list };
                            if list_ptr_next == list_ptr {
                                break;
                            }
                            let list_value =
                                unsafe { String::from(CStr::from_ptr((*elem_ptr).name).to_str()?) };
                            list.push(list_value);
                            elem_ptr = unsafe { (*elem_ptr).list.next as *const uci_element };
                        }
                        UciValue::List(list)
                    }
                    _ => {
                        return Err(Error::Message(format!(
                            "Cannot get values of a non-string or a non-list: {} {}",
                            key, opt.type_
                        )));
                    }
                };

                debug!(
                    "{}.{}.{}={}",
                    unsafe { CStr::from_ptr(pack.e.name) }.to_str()?,
                    unsafe { CStr::from_ptr(sect.e.name) }.to_str()?,
                    unsafe { CStr::from_ptr(opt.e.name) }.to_str()?,
                    value
                );
                Ok(value)
            }
            uci_type_UCI_TYPE_SECTION => {
                let sect = unsafe { *ptr.s };
                if sect.package.is_null() {
                    return Err(Error::Message(format!("uci package was null: {}", key)));
                }
                let pack = unsafe { *sect.package };
                let typ = unsafe { CStr::from_ptr(sect.type_).to_str()? };

                debug!(
                    "{}.{}={}",
                    unsafe { CStr::from_ptr(pack.e.name) }.to_str()?,
                    unsafe { CStr::from_ptr(sect.e.name) }.to_str()?,
                    typ
                );
                Ok(UciValue::String(String::from(typ)))
            }
            _ => return Err(Error::Message(format!("unsupported type: {}", last.type_))),
        }
    }

    /// Queries UCI (e.g. `package.section.key`)
    ///
    /// This also supports advanced syntax like `network.@interface[-1].ifname` (get ifname of last interface)
    ///
    /// An `Ok(result)` is guaranteed to be a valid ptr and ptr.last will be set.
    ///
    /// If the key could not be found `ptr.flags & UCI_LOOKUP_COMPLETE` will not be set, but the ptr is still valid.
    ///
    /// If `identifier` is assignment like `network.wan.proto="dhcp"`, `ptr.value` will be set.
    fn get_ptr(&mut self, identifier: &str) -> Result<UciPtr> {
        let mut ptr = uci_ptr {
            target: 0,
            flags: 0,
            p: ptr::null_mut(),
            s: ptr::null_mut(),
            o: ptr::null_mut(),
            last: ptr::null_mut(),
            package: ptr::null(),
            section: ptr::null(),
            option: ptr::null(),
            value: ptr::null(),
        };
        let raw = libuci_locked!(self, {
            let raw = CString::new(identifier)?.into_raw();
            let result = unsafe { uci_lookup_ptr(self.ctx, &mut ptr, raw, true) };
            if result != UCI_OK {
                return Err(Error::Message(format!(
                    "Could not parse uci key: {}, {}, {}",
                    identifier,
                    result,
                    self.get_last_error()
                        .unwrap_or_else(|_| String::from("Unknown"))
                )));
            }
            raw
        });
        debug!("{:?}", ptr);
        if !ptr.last.is_null() {
            Ok(UciPtr(ptr, raw))
        } else {
            Err(Error::Message(format!(
                "Cannot access null value: {}",
                identifier
            )))
        }
    }

    /// Obtains the most recent error from UCI as a string
    /// if no `last_error` is set, an `Err` is returned.
    fn get_last_error(&mut self) -> Result<String> {
        let mut raw: *mut std::os::raw::c_char = ptr::null_mut();
        libuci_locked!(self, {
            unsafe { uci_get_errorstr(self.ctx, &mut raw, ptr::null()) }
        });
        if raw.is_null() {
            return Err(Error::Message(String::from("last_error was null")));
        }
        match unsafe { CStr::from_ptr(raw) }.to_str() {
            Ok(o) => {
                let s = String::from(o);
                unsafe { libc::free(raw.cast::<std::os::raw::c_void>()) };
                Ok(s)
            }
            Err(e) => {
                unsafe { libc::free(raw.cast::<std::os::raw::c_void>()) };
                Err(e.into())
            }
        }
    }
}
