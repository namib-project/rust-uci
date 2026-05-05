use std::{
    ffi::{CStr, CString},
    option::Option as StdOption,
    ptr,
    sync::{Arc, Mutex},
};

use libuci_sys::{uci_commit, uci_element, uci_save, uci_to_section, uci_type_UCI_TYPE_PACKAGE};

use crate::{
    config::{handle_error, section::SectionIdent},
    error::Error,
    libuci_locked, Result, Uci,
};

use super::{
    ptr::{UciListIter, UciPtr},
    section::Section,
};

/// represents a single package in the config tree
/// parent to different [Section]s
pub struct Package {
    uci: Arc<Mutex<Uci>>,
    name: Arc<CString>,
}

impl Package {
    pub(crate) fn new(uci: Arc<Mutex<Uci>>, name: Arc<CString>) -> Package {
        Package { uci, name }
    }

    pub fn name(&self) -> Result<&str> {
        Ok(self.name.to_str()?)
    }

    pub(crate) fn ptr_opt<'a>(&'_ self, uci: &'a mut Uci) -> Result<StdOption<UciPtr<'a>>> {
        let mut ptr = UciPtr::new();
        ptr.target = uci_type_UCI_TYPE_PACKAGE;
        ptr.package = self.name.as_c_str().as_ptr();
        ptr.lookup(uci)
    }

    pub(crate) fn ptr<'a>(&'_ self, uci: &'a mut Uci) -> Result<UciPtr<'a>> {
        match self.ptr_opt(uci)? {
            Some(ptr) => Ok(ptr),
            None => Err(Error::EntryNotFound {
                entry_identifier: self.name()?.to_owned(),
            }),
        }
    }

    fn sections_impl<F: FnMut(&*const uci_element) -> bool>(
        &self,
        filter: F,
    ) -> Result<impl Iterator<Item = Section>> {
        let mut uci = self.uci.lock().unwrap();
        let ptr = match self.ptr_opt(&mut uci)? {
            Some(ptr) => unsafe { &(*ptr.p).sections },
            None => ptr::null(),
        };
        drop(uci);
        let uci = Arc::clone(&self.uci);
        let package = Arc::clone(&self.name);
        Ok(UciListIter::new(ptr).filter(filter).map(move |elem| {
            let sect = unsafe { uci_to_section(elem) };
            let type_ = unsafe { CStr::from_ptr((*sect).type_) }.to_owned();
            let name = unsafe { CStr::from_ptr((*elem).name) }.to_owned();
            Section::new(
                Arc::clone(&uci),
                Arc::clone(&package),
                Arc::new(type_),
                Arc::new(SectionIdent::Named(name)),
            )
        }))
    }

    pub fn sections(&self) -> Result<impl Iterator<Item = Section>> {
        self.sections_impl(|_| true)
    }

    pub fn sections_by_type(
        &self,
        type_: impl AsRef<str>,
    ) -> Result<impl Iterator<Item = Section>> {
        let type_ = CString::new(type_.as_ref())?;
        self.sections_impl(move |e| {
            let elem_type = unsafe { CStr::from_ptr((*uci_to_section(*e)).type_) };
            elem_type == type_.as_c_str()
        })
    }

    /// return a single [Section] by its name
    /// also works if the section is not defined yet
    pub fn section<T: AsRef<str>>(
        &self,
        type_: impl AsRef<str>,
        ident: impl Into<SectionIdent<T>>,
    ) -> Result<Section> {
        let type_ = CString::new(type_.as_ref())?;

        use SectionIdent::*;
        let ident = match ident.into() {
            Anonymous => Anonymous,
            Indexed(i) => Indexed(i),
            Named(n) => Named(CString::new(n.as_ref())?),
        };

        Ok(Section::new(
            Arc::clone(&self.uci),
            Arc::clone(&self.name),
            Arc::new(type_),
            Arc::new(ident),
        ))
    }

    /// save package delta to disk
    pub fn save(&mut self) -> Result<()> {
        let mut uci = self.uci.lock().unwrap();
        let pkg = self.ptr(&mut uci)?.p;
        let result = libuci_locked!(unsafe { uci_save(uci.ctx, pkg) });
        handle_error(&mut uci, result)?;
        Ok(())
    }

    /// commit package delta into real config on disk
    pub fn commit(&mut self) -> Result<()> {
        let mut uci = self.uci.lock().unwrap();
        let mut pkg = self.ptr(&mut uci)?.p;
        // the uci cli seems to set `override=false` too, not sure what it means
        let result = libuci_locked!(unsafe { uci_commit(uci.ctx, &raw mut pkg, false) });
        handle_error(&mut uci, result)?;
        Ok(())
    }
}
