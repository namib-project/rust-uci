use core::slice;
use std::{
    borrow::Cow,
    ffi::{CStr, CString},
    ops::DerefMut,
    option::Option as StdOption,
    sync::{Arc, Mutex},
};

use libuci_sys::{
    uci_add_list, uci_delete, uci_foreach_element, uci_option_type_UCI_TYPE_LIST,
    uci_option_type_UCI_TYPE_STRING, uci_set, uci_type_UCI_TYPE_OPTION,
};

use crate::{config::handle_error, error::Error, libuci_locked, Result, Uci};

use super::{
    ptr::UciPtr,
    section::{Section, SectionIdent},
};

pub type OptionMut = Option<true>;

/// represents an option within a [Section]
pub struct Option<const MUT: bool = false> {
    uci: Arc<Mutex<Uci>>,
    package: Arc<CString>,
    section: (Arc<CString>, Arc<SectionIdent<CString>>),
    name: Arc<CString>,
}

impl<const MUT: bool> Option<MUT> {
    pub(crate) fn new(
        uci: Arc<Mutex<Uci>>,
        package: Arc<CString>,
        section: (Arc<CString>, Arc<SectionIdent<CString>>),
        name: Arc<CString>,
    ) -> Option<MUT> {
        Option {
            uci,
            package,
            section,
            name,
        }
    }

    fn ptr<'a>(&'_ self, uci: &'a mut Uci) -> Result<StdOption<UciPtr<'a>>> {
        let section = match self.section().ptr(uci)? {
            Some(s) => s,
            None => return Ok(None),
        };

        let mut ptr = UciPtr::new();
        ptr.target = uci_type_UCI_TYPE_OPTION;
        ptr.p = section.p;
        ptr.s = section.s;
        ptr.option = self.name.as_ptr();
        ptr.lookup(uci)
    }

    fn ptr_ensure<'a>(&'_ mut self, uci: &'a mut Uci) -> Result<UciPtr<'a>> {
        let mut section = self.section();
        let section_ptr = section.ensure(Some(uci))?;

        // update ident to match newly created item
        self.section.1 = Arc::clone(&section.ident);

        let mut ptr = UciPtr::new();
        ptr.target = uci_type_UCI_TYPE_OPTION;
        ptr.p = section_ptr.p;
        ptr.s = section_ptr.s;
        ptr.option = self.name.as_ptr();
        Ok(ptr)
    }

    /// name of the option
    pub fn name(&self) -> &str {
        self.name.to_str().unwrap()
    }

    pub fn section(&self) -> Section {
        Section::new(
            Arc::clone(&self.uci),
            Arc::clone(&self.package),
            Arc::clone(&self.section.0),
            Arc::clone(&self.section.1),
        )
    }

    /// returns the current value of the option, None if not set
    pub fn get<'a>(&'a self) -> Result<StdOption<Value>> {
        let mut uci = self.uci.lock().unwrap();
        let ptr = match self.ptr(&mut uci)? {
            Some(ptr) => ptr,
            None => return Ok(None),
        };

        let opt = ptr.o;

        #[allow(non_upper_case_globals)]
        match unsafe { *opt }.type_ {
            uci_option_type_UCI_TYPE_STRING => {
                let raw = unsafe { CStr::from_ptr((*opt).v.string) };
                Ok(Value::String(raw.to_str()?.into()))
            }
            uci_option_type_UCI_TYPE_LIST => {
                let mut result = Vec::new();
                unsafe {
                    uci_foreach_element(&(*opt).v.list, |elem| {
                        let raw = CStr::from_ptr((*elem).name);
                        result.push(raw);
                    })
                };
                Ok(Value::List(
                    result
                        .into_iter()
                        .map(|cstr| cstr.to_str().map_err(Into::into).map(Into::into))
                        .collect::<Result<Vec<_>>>()?,
                ))
            }
            t => return Err(Error::Message(format!("Unexpected option type: {t}"))),
        }
        .map(Some)
    }
}

impl OptionMut {
    /// sets the value of the option, overriding the previous value
    /// will create the [Package] or [Section] along the way if they do
    /// not exist
    pub fn set(&mut self, value: impl Into<Value>) -> Result<()> {
        let uci = Arc::clone(&self.uci);
        let mut uci = uci.lock().unwrap();
        let ptr = self.ptr_ensure(&mut uci)?;
        let mut ptr: UciPtr<'static> = unsafe { std::mem::transmute(ptr) };
        match value.into() {
            Value::String(s) => {
                let value = CString::new(s)?;
                ptr.value = value.as_ptr();

                let result = libuci_locked!(unsafe { uci_set(uci.ctx, &raw mut *ptr.deref_mut()) });
                handle_error(&mut uci, result)?;
            }
            Value::List(items) => {
                libuci_locked!({
                    let result = unsafe { uci_delete(uci.ctx, &raw mut *ptr.deref_mut()) };
                    handle_error(&mut uci, result)?;
                    for item in items {
                        let val = CString::new(item)?;
                        ptr.value = val.as_ptr();
                        let result = unsafe { uci_add_list(uci.ctx, &raw mut *ptr.deref_mut()) };
                        handle_error(&mut uci, result)?;
                    }
                });
            }
        };
        Ok(())
    }

    /// adds a value to the existing value
    /// behaves like `uci add_list` which will:
    /// - create the option if it doesn't exist (not as a list)
    /// - turn a single-value option into a list
    ///
    /// returns the resulting value
    pub fn add_list(&mut self, value: impl AsRef<str>) -> Result<()> {
        let value = CString::new(value.as_ref())?;

        let uci = Arc::clone(&self.uci);
        let mut uci = uci.lock().unwrap();
        let mut ptr = self.ptr_ensure(&mut uci)?;
        ptr.value = value.as_ptr();

        let mut uci = self.uci.lock().unwrap();
        let result = libuci_locked!(unsafe { uci_add_list(uci.ctx, &raw mut *ptr.deref_mut()) });
        handle_error(&mut uci, result)?;

        Ok(())
    }
}

/// represents the value of an [Option]
#[derive(Debug)]
pub enum Value {
    String(String),
    List(Vec<String>),
}

impl Value {
    pub fn list<'a, I: Into<Cow<'a, str>>>(val: impl IntoIterator<Item = I>) -> Self {
        let v = val.into_iter().map(|s| s.into().to_string()).collect();
        Self::List(v)
    }

    pub fn to_str(&self) -> StdOption<&str> {
        match self {
            Value::String(n) => Some(n),
            _ => None,
        }
    }
}

pub enum ValueIter<'a> {
    String(StdOption<&'a String>),
    List(slice::Iter<'a, String>),
}

impl<'a> Iterator for ValueIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> StdOption<Self::Item> {
        match self {
            ValueIter::String(opt) => opt.take(),
            ValueIter::List(iter) => iter.next(),
        }
        .map(String::as_str)
    }
}

impl<'a> IntoIterator for &'a Value {
    type Item = &'a str;

    type IntoIter = ValueIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            Value::String(val) => ValueIter::String(Some(val)),
            Value::List(items) => ValueIter::List(items.iter()),
        }
    }
}

impl<T> From<T> for Value
where
    T: ToString,
{
    fn from(value: T) -> Self {
        Self::String(value.to_string())
    }
}

impl<'a> PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::String(l0), Self::String(r0)) => l0 == r0,
            (Self::List(l0), Self::List(r0)) => l0 == r0,
            _ => false,
        }
    }
}
