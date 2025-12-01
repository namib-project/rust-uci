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
//! When crosscompiling it may be useful to set BINDGEN_TARGET to instruct what
//! target bindgen is built for.
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
    uci_type_UCI_TYPE_OPTION, uci_type_UCI_TYPE_SECTION, uci_unload, uci_validate_text,
    UCI_ERR_NOTFOUND, UCI_OK,
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

/// Casts a pointer `ptr` of a struct `container` member to the containing struct pointer.
///
/// # Safety
/// The caller must ensure that `$container.$field` has the same type as `$ptr` points to.
macro_rules! container_of {
    ($ptr:expr, $container:ty, $field:ident) => {{
        $ptr.cast::<u8>()
            .wrapping_sub(std::mem::offset_of!($container, $field))
            .cast::<$container>()
    }};
}

/// casts an uci_list pointer to the containing uci_element.
///
/// # Safety
/// The caller must ensure that `ptr` points to a list which is member of an uci_element.
/// The `ptr` must not point to a list which is not contained in an uci_element.
pub unsafe fn list_to_element(ptr: *const uci_list) -> *const uci_element {
    // safety: uci_element.list has type uci_list, ptr points to uci_list
    container_of!(ptr, uci_element, list)
}

/// casts an [`uci_element`] pointer to the containing [`uci_section`].
///
/// # Safety
/// The caller must ensure that `ptr` points to an element which is member of an [`uci_section`].
/// The `ptr` must not point to an element which is not contained in an uci_element.
pub unsafe fn uci_to_section(ptr: *const uci_element) -> *const uci_section {
    // safety: uci_section.e has type uci_element, ptr points to uci_element
    container_of!(ptr, uci_section, e)
}

/// mimics the C-macro `uci_foreach_element`
///
/// Note: the list head is not considered as a data node, and is skipped during iteration.
///
/// # Safety
/// The caller must ensure, that list points to a valid uci_list,
/// where each element is contained in a [`uci_element`] struct,
/// except for the list head.
///
/// The caller must not mutate the list during iteration (e.g. via `func`).
pub unsafe fn uci_foreach_element(list: *const uci_list, mut func: impl FnMut(*const uci_element)) {
    if list.is_null() {
        return;
    }

    let mut node = (*list).next;
    while !node.is_null() && node.cast_const() != list {
        let element = list_to_element(node.cast_const());
        func(element);
        node = (*node).next;
    }
}

#[cfg(test)]
mod tests {
    use std::ptr;

    use crate::{
        list_to_element, uci_element, uci_foreach_element, uci_list, uci_section, uci_to_section,
    };

    #[test]
    fn list_to_element_succeeds() {
        let elem = uci_element {
            list: uci_list {
                next: ptr::null_mut(),
                prev: ptr::null_mut(),
            },
            type_: 0,
            name: ptr::null_mut(),
        };

        assert_eq!(&raw const elem, unsafe {
            list_to_element(&raw const elem.list)
        });
    }

    #[test]
    fn uci_to_section_succeeds() {
        let section = uci_section {
            e: uci_element {
                list: uci_list {
                    next: ptr::null_mut(),
                    prev: ptr::null_mut(),
                },
                type_: 42,
                name: ptr::null_mut(),
            },
            options: uci_list {
                next: ptr::null_mut(),
                prev: ptr::null_mut(),
            },
            package: ptr::null_mut(),
            anonymous: false,
            type_: ptr::null_mut(),
        };

        assert_eq!(&raw const section, unsafe {
            uci_to_section(&raw const section.e)
        });
    }
    #[test]
    fn uci_foreach_element_succeeds() {
        let mut head = uci_list {
            next: ptr::null_mut(),
            prev: ptr::null_mut(),
        };
        let mut e1 = uci_element {
            list: uci_list {
                prev: ptr::null_mut(),
                next: ptr::null_mut(),
            },
            type_: 0,
            name: ptr::null_mut(),
        };
        let mut e2 = e1;
        let mut e3 = e2;

        head.next = &raw mut e1.list;
        head.prev = &raw mut e3.list;

        e1.list.prev = &raw mut head;
        e1.list.next = &raw mut e2.list;
        e1.type_ = 1;

        e2.list.prev = &raw mut e1.list;
        e2.list.next = &raw mut e3.list;
        e2.type_ = 2;

        e3.list.prev = &raw mut e2.list;
        e3.list.next = &raw mut head;
        e3.type_ = 3;

        let mut visited = vec![];
        unsafe {
            uci_foreach_element(&raw const head, |e: *const uci_element| {
                visited.push((*e).type_);
            })
        };
        assert_eq!(visited, [1, 2, 3]);
    }
}
