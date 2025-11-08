use windows::Win32::System::Diagnostics::Debug::IMAGE_DIRECTORY_ENTRY_IMPORT;
use windows::Win32::System::LibraryLoader::LoadLibraryW;
use windows::core::PCWSTR;

use windows::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_IMPORT_DESCRIPTOR};

#[cfg(target_pointer_width = "64")]
mod pe_types {
    use windows::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_OPTIONAL_HEADER64};

    pub type ImageNtHeaders = IMAGE_NT_HEADERS64;
    pub type ImageOptionalHeader = IMAGE_OPTIONAL_HEADER64;
}

#[cfg(target_pointer_width = "32")]
mod pe_types {
    use windows::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS32, IMAGE_OPTIONAL_HEADER32};

    pub type ImageNtHeaders = IMAGE_NT_HEADERS32;
    pub type ImageOptionalHeader = IMAGE_OPTIONAL_HEADER32;
}

fn to_wide_string(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

struct Executable {}

trait PEFile {
    fn get_base_address(&self) -> Option<*const u8>;
    fn get_dos_header(&self) -> Option<&IMAGE_DOS_HEADER> {
        let base_address = self.get_base_address();
        if base_address.is_none() {
            return None;
        }

        let dos_header = base_address.unwrap() as *const IMAGE_DOS_HEADER;
        if (unsafe { *dos_header }).e_magic != 0x5A4D {
            return None;
        }

        return Some(unsafe { &*dos_header });
    }

    fn get_nt_headers(&self) -> Option<&pe_types::ImageNtHeaders> {
        let base_address = self.get_base_address();
        let dos_header = self.get_dos_header();

        if base_address.is_none() || dos_header.is_none() {
            return None;
        }

        let nt_headers_offset = dos_header?.e_lfanew as isize;
        let nt_headers =
            unsafe { base_address?.offset(nt_headers_offset) } as *const pe_types::ImageNtHeaders;

        return Some(unsafe { &*nt_headers });
    }

    fn get_optional_header(&self) -> Option<&pe_types::ImageOptionalHeader> {
        return Some(&self.get_nt_headers()?.OptionalHeader);
    }

    fn rva_to_va(&self, rva: u32) -> Option<*const u8> {
        return Some(unsafe { self.get_base_address()?.add(rva.try_into().unwrap()) });
    }

    fn rva_to_ptr<T: Sized>(&self, rva: u32) -> Option<*const T> {
        let va = self.rva_to_va(rva);
        if va.is_none() {
            return None;
        }

        return Some(va.unwrap() as *const T);
    }

    fn rva_to_stuct<T: Sized>(&self, rva: u32) -> Option<&T> {
        let ptr: Option<*const T> = self.rva_to_ptr(rva);
        if ptr.is_none() {
            return None;
        }

        return Some(unsafe { &*ptr.unwrap() });
    }
}

impl PEFile for windows::Win32::Foundation::HMODULE {
    fn get_base_address(&self) -> Option<*const u8> {
        if self.is_invalid() {
            return None;
        }

        return Some(self.0 as *const u8);
    }
}

fn load_library(lib: &str) -> Option<windows::Win32::Foundation::HMODULE> {
    let wide_path = to_wide_string(lib);
    return unsafe { LoadLibraryW(PCWSTR::from_raw(wide_path.as_ptr())).ok() };
}

fn load_imports<T: PEFile>(pe: &T) -> bool {
    let base_address = pe.get_base_address();
    let optional_header = pe.get_optional_header();

    if base_address.is_none() || optional_header.is_none() {
        return false;
    }

    let import_directory =
        optional_header.unwrap().DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT.0 as usize];

    let descriptor_ptr: Option<*const IMAGE_IMPORT_DESCRIPTOR> =
        pe.rva_to_ptr(import_directory.VirtualAddress);

    if descriptor_ptr.is_none() {
        return false;
    }

    let mut offset: usize = 0;
    loop {
        let index = offset;
        offset += 1;

        let descriptor = unsafe { descriptor_ptr.unwrap().add(index) };
    }

    return false;
}

unsafe fn load_executable_as_library(lib: &str) -> Option<Executable> {
    let module = load_library(lib);
    if module.is_none() {
        return None;
    }

    let loaded = load_imports(&module.unwrap());
    if !loaded {
        return None;
    }

    return None;
}

fn main() {
    unsafe {
        load_executable_as_library("ntdll.dll");
    }
}
