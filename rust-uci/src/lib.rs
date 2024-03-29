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
use std::{
    ffi::{CStr, CString},
    ops::{Deref, DerefMut},
};

use libuci_sys::{
    uci_alloc_context, uci_commit, uci_context, uci_delete, uci_free_context, uci_get_errorstr,
    uci_lookup_ptr, uci_option_type_UCI_TYPE_STRING, uci_ptr, uci_ptr_UCI_LOOKUP_COMPLETE,
    uci_revert, uci_save, uci_set, uci_set_confdir, uci_set_savedir, uci_type_UCI_TYPE_OPTION,
    uci_type_UCI_TYPE_SECTION, uci_unload,
};
use log::debug;

use crate::error::{Error, Result};

#[allow(clippy::cast_possible_wrap)]
const UCI_OK: i32 = libuci_sys::UCI_OK as i32;

/// Contains the native `uci_context`
pub struct Uci(*mut uci_context);

impl Drop for Uci {
    fn drop(&mut self) {
        unsafe { uci_free_context(self.0) }
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
        let ctx = unsafe { uci_alloc_context() };
        if !ctx.is_null() {
            Ok(Uci(ctx))
        } else {
            Err(Error::Message(String::from("Could not alloc uci context")))
        }
    }

    /// Sets the config directory of UCI, this is `/etc/config` by default.
    pub fn set_config_dir(&mut self, config_dir: &str) -> Result<()> {
        let result = unsafe {
            let raw = CString::new(config_dir)?;
            uci_set_confdir(
                self.0,
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
    }

    /// Sets the save directory of UCI, this is `/tmp/.uci` by default.
    pub fn set_save_dir(&mut self, save_dir: &str) -> Result<()> {
        let result = unsafe {
            let raw = CString::new(save_dir)?;
            uci_set_savedir(
                self.0,
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
    }

    /// Delete an option or section in UCI.
    /// UCI will keep the delta changes in a temporary location until `commit()` or `revert()` is called.
    ///
    /// Allowed keys are like `network.wan.proto`, `network.@interface[-1].iface`, `network.wan` and `network.@interface[-1]`
    ///
    /// if the deletion failed an `Err` is returned.
    pub fn delete(&mut self, identifier: &str) -> Result<()> {
        let mut ptr = self.get_ptr(identifier)?;
        let result = unsafe { uci_delete(self.0, &mut ptr.0) };
        if result != UCI_OK {
            return Err(Error::Message(format!(
                "Could not delete uci key: {}, {}, {}",
                identifier,
                result,
                self.get_last_error()
                    .unwrap_or_else(|_| String::from("Unknown"))
            )));
        }
        let result = unsafe { uci_save(self.0, ptr.p) };
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
    }

    /// Revert changes to an option, section or package
    ///
    /// Allowed keys are like `network`, `network.wan.proto`, `network.@interface[-1].iface`, `network.wan` and `network.@interface[-1]`
    ///
    /// if the deletion failed an `Err` is returned.
    pub fn revert(&mut self, identifier: &str) -> Result<()> {
        let mut ptr = self.get_ptr(identifier)?;
        let result = unsafe { uci_revert(self.0, &mut ptr.0) };
        if result != UCI_OK {
            return Err(Error::Message(format!(
                "Could not revert uci key: {}, {}, {}",
                identifier,
                result,
                self.get_last_error()
                    .unwrap_or_else(|_| String::from("Unknown"))
            )));
        }
        let result = unsafe { uci_save(self.0, ptr.p) };
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
        let mut ptr = self.get_ptr(format!("{}={}", identifier, val).as_ref())?;
        if ptr.value.is_null() {
            return Err(Error::Message(format!(
                "parsed value is null: {}={}",
                identifier, val
            )));
        }
        let result = unsafe { uci_set(self.0, &mut ptr.0) };
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
        let result = unsafe { uci_save(self.0, ptr.p) };
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
    }

    /// Commit all changes to the specified package
    /// writing the temporary delta to the config file
    pub fn commit(&mut self, package: &str) -> Result<()> {
        let mut ptr = self.get_ptr(package)?;
        let result = unsafe { uci_commit(self.0, &mut ptr.p, false) };
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
                uci_unload(self.0, ptr.p);
            }
        }
        Ok(())
    }

    /// Queries an option value or section type from UCI.
    /// If a key has been changed in the delta, the updated value will be returned.
    ///
    /// Allowed keys are like `network.wan.proto`, `network.@interface[-1].iface`, `network.lan` and `network.@interface[-1]`
    ///
    /// if the entry does not exist an `Err` is returned.
    pub fn get(&mut self, key: &str) -> Result<String> {
        let ptr = self.get_ptr(key)?;
        if ptr.flags & uci_ptr_UCI_LOOKUP_COMPLETE == 0 {
            return Err(Error::Message(format!("Lookup failed: {}", key)));
        }
        let last = unsafe { *ptr.last };
        #[allow(non_upper_case_globals)]
        match last.type_ {
            uci_type_UCI_TYPE_OPTION => {
                let opt = unsafe { *ptr.o };
                if opt.type_ != uci_option_type_UCI_TYPE_STRING {
                    return Err(Error::Message(format!(
                        "Cannot get string value of non-string: {} {}",
                        key, opt.type_
                    )));
                }
                if opt.section.is_null() {
                    return Err(Error::Message(format!("uci section was null: {}", key)));
                }
                let sect = unsafe { *opt.section };
                if sect.package.is_null() {
                    return Err(Error::Message(format!("uci package was null: {}", key)));
                }
                let pack = unsafe { *sect.package };
                let value = unsafe { CStr::from_ptr(opt.v.string).to_str()? };

                debug!(
                    "{}.{}.{}={}",
                    unsafe { CStr::from_ptr(pack.e.name) }.to_str()?,
                    unsafe { CStr::from_ptr(sect.e.name) }.to_str()?,
                    unsafe { CStr::from_ptr(opt.e.name) }.to_str()?,
                    value
                );
                Ok(String::from(value))
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
                Ok(String::from(typ))
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
        let raw = CString::new(identifier)?.into_raw();
        let result = unsafe { uci_lookup_ptr(self.0, &mut ptr, raw, true) };
        if result != UCI_OK {
            return Err(Error::Message(format!(
                "Could not parse uci key: {}, {}, {}",
                identifier,
                result,
                self.get_last_error()
                    .unwrap_or_else(|_| String::from("Unknown"))
            )));
        }
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
        unsafe { uci_get_errorstr(self.0, &mut raw, ptr::null()) };
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
