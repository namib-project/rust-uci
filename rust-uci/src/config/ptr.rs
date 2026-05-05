use std::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
    option::Option as StdOption,
    ptr,
};

use libuci_sys::{
    list_to_element, uci_element, uci_list, uci_lookup_ptr, uci_ptr, uci_ptr_UCI_LOOKUP_COMPLETE,
    uci_type_UCI_TYPE_UNSPEC,
};

use crate::{config::handle_error, libuci_locked, Result, Uci};

/// mimicks the `uci_foreach_element_safe` macro in libuci
/// supposedly deletion safe
pub(super) struct UciListIter<'a> {
    list: *const uci_list,   // head of the list, doesn't change
    ptr: *const uci_element, // next element
    tmp: *const uci_element, // element after ptr
    _lt: &'a PhantomData<()>,
}

impl<'a> UciListIter<'a> {
    pub fn new(list: *const uci_list) -> Self {
        let ptr = if list.is_null() {
            ptr::null()
        } else {
            unsafe { list_to_element((*list).next) }
        };
        let tmp = if ptr.is_null() {
            ptr::null()
        } else {
            unsafe { list_to_element((*ptr).list.next) }
        };
        Self {
            list,
            ptr,
            tmp,
            _lt: &PhantomData,
        }
    }
}

impl<'a> Iterator for UciListIter<'a> {
    type Item = *const uci_element;

    fn next(&mut self) -> StdOption<Self::Item> {
        if self.ptr.is_null() {
            return None;
        }
        if unsafe { &raw const (*self.ptr).list } == self.list {
            return None;
        }

        let elem = self.ptr;

        self.ptr = self.tmp;
        self.tmp = unsafe { list_to_element((*self.ptr).list.next) };

        Some(elem)
    }
}

pub(crate) struct UciPtr<'a> {
    ptr: uci_ptr,
    _lt: &'a PhantomData<()>,
}

impl Deref for UciPtr<'_> {
    type Target = uci_ptr;

    fn deref(&self) -> &Self::Target {
        &self.ptr
    }
}

impl DerefMut for UciPtr<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.ptr
    }
}

impl<'a> UciPtr<'a> {
    pub fn new() -> UciPtr<'static> {
        let ptr = uci_ptr {
            target: uci_type_UCI_TYPE_UNSPEC,
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
        UciPtr {
            ptr,
            _lt: &PhantomData,
        }
    }

    pub fn lookup<'b>(&'_ mut self, uci: &'b mut Uci) -> Result<StdOption<UciPtr<'b>>> {
        let mut ptr = self.ptr.clone();
        let result =
            libuci_locked!(unsafe { uci_lookup_ptr(uci.ctx, &mut ptr, ptr::null_mut(), true) });
        let ptr = match handle_error(uci, result)? {
            Some(_) => {
                if ptr.flags & uci_ptr_UCI_LOOKUP_COMPLETE == 0 {
                    return Ok(None);
                }
                ptr
            }
            None => return Ok(None),
        };
        Ok(Some(UciPtr {
            ptr,
            _lt: &PhantomData,
        }))
    }
}
