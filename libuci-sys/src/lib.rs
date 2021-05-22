// Copyright 2021, Benjamin Ludewig
// SPDX-License-Identifier: MIT OR Apache-2.0

//! FFI bindings to OpenWRT UCI
//!
//! This crate provides an unsafe interface to OpenWRT's Unified Configuration Interface C-Library.
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

pub use bindings::{
    uci_add_delta_path, uci_add_list, uci_add_section, uci_alloc_context, uci_backend, uci_command,
    uci_commit, uci_context, uci_del_list, uci_delete, uci_delta, uci_element, uci_export,
    uci_flags, uci_free_context, uci_get_errorstr, uci_hash_options, uci_import, uci_list,
    uci_list_configs, uci_load, uci_lookup_next, uci_lookup_ptr, uci_option, uci_option_type,
    uci_option_type_UCI_TYPE_STRING, uci_package, uci_parse_argument, uci_parse_context,
    uci_parse_option, uci_parse_ptr, uci_parse_section, uci_perror, uci_ptr,
    uci_ptr_UCI_LOOKUP_COMPLETE, uci_rename, uci_reorder_section, uci_revert, uci_save,
    uci_section, uci_set, uci_set_backend, uci_set_confdir, uci_set_savedir, uci_type,
    uci_type_UCI_TYPE_OPTION, uci_type_UCI_TYPE_SECTION, uci_unload, uci_validate_text, UCI_OK,
};

#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(dead_code)]
mod bindings {
    use std::ffi::CStr;

    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

    impl core::fmt::Debug for uci_option {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("uci_option")
                .field("e", &self.e)
                .field("section", unsafe { &self.section.as_ref() })
                .field("type", &self.type_)
                .finish()
        }
    }

    impl core::fmt::Debug for uci_ptr {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            let package = unsafe { self.package.as_ref().map(|r| CStr::from_ptr(r)) };
            let section = unsafe { self.section.as_ref().map(|r| CStr::from_ptr(r)) };
            let option = unsafe { self.option.as_ref().map(|r| CStr::from_ptr(r)) };
            let value = unsafe { self.value.as_ref().map(|r| CStr::from_ptr(r)) };
            f.debug_struct("uci_ptr")
                .field("target", &self.target)
                .field("flags", &self.flags)
                .field("p", unsafe { &self.p.as_ref() })
                .field("s", unsafe { &self.s.as_ref() })
                .field("o", unsafe { &self.o.as_ref() })
                .field("last", unsafe { &self.last.as_ref() })
                .field("package", &package.map(|v| v.to_str()))
                .field("section", &section.map(|v| v.to_str()))
                .field("option", &option.map(|v| v.to_str()))
                .field("value", &value.map(|v| v.to_str()))
                .finish()
        }
    }
}
