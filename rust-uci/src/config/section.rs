use std::{
    ffi::{CStr, CString},
    iter,
    ops::DerefMut,
    option::Option as StdOption,
    ptr,
    sync::{Arc, Mutex},
};

use libuci_sys::{
    uci_add_section, uci_ptr_UCI_LOOKUP_EXTENDED, uci_set, uci_type_UCI_TYPE_SECTION,
};

use crate::{
    config::{handle_error, option::OptionMut},
    libuci_locked, Result, Uci,
};

use super::{
    option::Option,
    package::Package,
    ptr::{UciListIter, UciPtr},
};

pub enum SectionIdent<T> {
    Anonymous,
    Indexed(i32),
    Named(T),
}

impl<T> SectionIdent<T>
where
    T: AsRef<CStr>,
{
    pub(crate) fn inner_ident(&self, type_: impl AsRef<CStr>) -> StdOption<CString> {
        match self {
            SectionIdent::Anonymous => None,
            SectionIdent::Indexed(i) => {
                let type_ = type_.as_ref().to_bytes();
                let indexer = format!("[{i}]").into_bytes();
                let ident: Vec<_> = iter::once('@' as u8)
                    .chain(type_.into_iter().copied())
                    .chain(indexer)
                    .collect();
                Some(CString::new(ident).unwrap())
            }
            SectionIdent::Named(name) => Some(name.as_ref().to_owned()),
        }
    }
}

impl<'a> From<&'a str> for SectionIdent<&'a str> {
    fn from(value: &'a str) -> Self {
        Self::Named(value)
    }
}

impl From<String> for SectionIdent<String> {
    fn from(value: String) -> Self {
        Self::Named(value)
    }
}

impl From<i32> for SectionIdent<String> {
    fn from(value: i32) -> Self {
        Self::Indexed(value)
    }
}

impl From<()> for SectionIdent<String> {
    fn from(_value: ()) -> Self {
        Self::Anonymous
    }
}

/// represents a single section
/// parent to different [Option]s
pub struct Section {
    uci: Arc<Mutex<Uci>>,
    package: Arc<CString>,
    pub(crate) type_: Arc<CString>,
    pub(crate) ident: Arc<SectionIdent<CString>>,
}

impl Section {
    pub(crate) fn new(
        uci: Arc<Mutex<Uci>>,
        package: Arc<CString>,
        type_: Arc<CString>,
        ident: Arc<SectionIdent<CString>>,
    ) -> Self {
        Self {
            uci,
            package,
            type_,
            ident,
        }
    }

    pub(crate) fn ptr<'a>(&'_ self, uci: &'a mut Uci) -> Result<StdOption<UciPtr<'a>>> {
        let mut ptr = UciPtr::new();

        let _ident_raw = match &*self.ident {
            SectionIdent::Anonymous => return Ok(None),
            i @ SectionIdent::Indexed(_) => {
                let ident = i.inner_ident(self.type_.as_ref()).unwrap();
                ptr.section = ident.as_ptr();
                ptr.flags |= uci_ptr_UCI_LOOKUP_EXTENDED;
                Some(ident) // keep this alive
            }
            SectionIdent::Named(s) => {
                ptr.section = s.as_ptr();
                None
            }
        };

        ptr.target = uci_type_UCI_TYPE_SECTION;
        ptr.package = self.package.as_c_str().as_ptr();
        ptr.lookup(uci)
    }

    pub(crate) fn ensure<'a>(&'_ mut self, uci: StdOption<&'a mut Uci>) -> Result<UciPtr<'a>> {
        let mut guard = None;
        let uci = match uci {
            Some(uci) => uci,
            None => {
                guard.replace(self.uci.lock().unwrap());
                guard.as_deref_mut().unwrap()
            }
        };
        let pkg_ptr = self.package().ptr(uci)?;

        let mut ptr = UciPtr::new();
        ptr.target = uci_type_UCI_TYPE_SECTION;
        ptr.p = pkg_ptr.p;

        let result = match self.ident.as_ref() {
            SectionIdent::Anonymous => {
                let mut section_ptr = ptr::null_mut();
                let result = libuci_locked!(unsafe {
                    uci_add_section(uci.ctx, ptr.p, self.type_.as_ptr(), &mut section_ptr)
                });
                ptr.s = section_ptr;

                // persist created name in the ident
                let name = unsafe { CStr::from_ptr((*section_ptr).e.name) }.to_owned();
                self.ident = Arc::new(SectionIdent::Named(name));

                result
            }
            i @ SectionIdent::Indexed(_) => {
                let ident = i.inner_ident(self.type_.as_ref()).unwrap();
                ptr.flags |= uci_ptr_UCI_LOOKUP_EXTENDED;
                ptr.section = ident.as_c_str().as_ptr();
                ptr.value = self.type_.as_ptr();
                let result = libuci_locked!(unsafe { uci_set(uci.ctx, ptr.deref_mut()) });
                ptr.section = ptr::null(); // CString is dropped after this context
                result
            }
            SectionIdent::Named(name) => {
                ptr.section = name.as_ptr();
                ptr.value = self.type_.as_ptr();
                libuci_locked!(unsafe { uci_set(uci.ctx, ptr.deref_mut()) })
            }
        };
        handle_error(uci, result)?;

        Ok(ptr)
    }

    pub fn create(&mut self) -> Result<()> {
        self.ensure(None)?;
        Ok(())
    }

    /// returns the name of the section item, None if it's anonymous
    pub fn name(&self) -> StdOption<String> {
        let ident = self.ident.as_ref().inner_ident(self.type_.as_ref());
        ident.map(|cstr| cstr.into_string().unwrap())
    }

    /// returns the type of the section
    pub fn type_(&self) -> &str {
        self.type_.to_str().unwrap()
    }

    /// lists all options in this section
    pub fn options(&self) -> Result<impl Iterator<Item = OptionMut>> {
        let mut uci = self.uci.lock().unwrap();
        let section = self.ptr(&mut uci)?.map(|p| unsafe { *p.s });
        let option_list = section
            .map(|l| &raw const l.options)
            .unwrap_or_else(ptr::null);

        let uci = Arc::clone(&self.uci);
        let package = Arc::clone(&self.package);
        let section_type = Arc::clone(&self.type_);
        let section_ident = Arc::clone(&self.ident);
        Ok(UciListIter::new(option_list).map(move |elem| {
            let name = unsafe { CStr::from_ptr((*elem).name) }.to_owned();
            Option::new(
                Arc::clone(&uci),
                Arc::clone(&package),
                (Arc::clone(&section_type), Arc::clone(&section_ident)),
                Arc::new(name),
            )
        }))
    }

    /// returns a specific [Option] by name
    /// also works if the option is not defined yet
    pub fn option(&self, name: impl AsRef<str>) -> Result<Option> {
        let name = CString::new(name.as_ref())?;
        Ok(Option::<false>::new(
            Arc::clone(&self.uci),
            Arc::clone(&self.package),
            (Arc::clone(&self.type_), Arc::clone(&self.ident)),
            Arc::new(name),
        ))
    }

    /// works like [Self::option], but ensures the section exists first
    /// this then allows to modify the option
    /// (which requires the section to exist)
    pub fn option_mut(&mut self, name: impl AsRef<str>) -> Result<OptionMut> {
        self.ensure(None)?;
        let name = CString::new(name.as_ref())?;
        Ok(Option::<true>::new(
            Arc::clone(&self.uci),
            Arc::clone(&self.package),
            (Arc::clone(&self.type_), Arc::clone(&self.ident)),
            Arc::new(name),
        ))
    }

    pub fn package(&self) -> Package {
        Package::new(Arc::clone(&self.uci), Arc::clone(&self.package))
    }
}
