use windows::Win32::System::Diagnostics::Debug::IMAGE_DIRECTORY_ENTRY_IMPORT;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA, LoadLibraryW};
use windows::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, VirtualProtect};
use windows::core::{PCSTR, PCWSTR};

use windows::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR,
};

#[cfg(target_pointer_width = "64")]
mod pe_types {
    use windows::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_OPTIONAL_HEADER64};

    pub type ImageNtHeaders = IMAGE_NT_HEADERS64;
    pub type ImageOptionalHeader = IMAGE_OPTIONAL_HEADER64;

    pub const IMAGE_ORDINAL_FLAG: usize = 0x8000000000000000;
}

#[cfg(target_pointer_width = "32")]
mod pe_types {
    use windows::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS32, IMAGE_OPTIONAL_HEADER32};

    pub type ImageNtHeaders = IMAGE_NT_HEADERS32;
    pub type ImageOptionalHeader = IMAGE_OPTIONAL_HEADER32;

    pub const IMAGE_ORDINAL_FLAG: usize = 0x80000000;
}

fn image_snap_by_ordinal(ordinal: usize) -> bool {
    return (ordinal & pe_types::IMAGE_ORDINAL_FLAG) != 0;
}

fn image_ordinal(ordinal: usize) -> usize {
    return ordinal & 0xffff;
}

fn to_wide_string(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

struct Executable {
    handle: windows::Win32::Foundation::HMODULE,
    entry_point: fn(),
}

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

    fn get_entry_point(&self) -> Option<fn()> {
        let optional_header = self.get_optional_header();
        let pointer = self.rva_to_va(optional_header?.AddressOfEntryPoint);
        if pointer.is_none() {
            return None;
        }

        let entry_point: fn() = unsafe { std::mem::transmute(pointer.unwrap()) };
        return Some(entry_point);
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

fn load_imports_for_library<T: PEFile>(
    pe: &T,
    lib: PCSTR,
    address_table: *const *const u8,
    name_table: *const usize,
) -> bool {
    let lib_handle = unsafe { LoadLibraryA(lib) };
    if lib_handle.is_err() {
        return false;
    }

    let handle = lib_handle.unwrap();

    let mut offset: usize = 0;
    loop {
        let index = offset;
        offset += 1;

        let name_table_entry = unsafe { *name_table.add(index) };
        let address_table_entry_ptr = unsafe { address_table.add(index) };

        if name_table_entry == 0 {
            break;
        }

        let name;

        if image_snap_by_ordinal(name_table_entry) {
            let ordinal = image_ordinal(name_table_entry);
            name = PCSTR::from_raw(ordinal as *const u8);
        } else {
            let name_import: Option<*const u8> = pe.rva_to_ptr(name_table_entry as u32);
            if name_import.is_none() {
                return false;
            }

            let name_offset = core::mem::offset_of!(IMAGE_IMPORT_BY_NAME, Name);
            let name_address = unsafe { name_import.unwrap().add(name_offset) };
            name = PCSTR::from_raw(name_address);
        }

        let address = unsafe { GetProcAddress(handle, name) };
        if address.is_none() {
            return false;
        }

        let function_ptr = address.unwrap() as *const u8;

        let mut old_protect = PAGE_EXECUTE_READWRITE;
        unsafe {
            let res = VirtualProtect(
                address_table_entry_ptr as *const core::ffi::c_void,
                8,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            );

            if res.is_err() {
                return false;
            }
        };

        unsafe { *(address_table_entry_ptr as *mut *const u8) = function_ptr };

        unsafe {
            let res = VirtualProtect(
                address_table_entry_ptr as *const core::ffi::c_void,
                8,
                old_protect,
                &mut old_protect,
            );

            if res.is_err() {
                return false;
            }
        };
    }

    return true;
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

        let descriptor = unsafe { *descriptor_ptr.unwrap().add(index) };

        if descriptor.Name == 0 {
            break;
        }

        let name_ptr = pe.rva_to_va(descriptor.Name);
        if name_ptr.is_none() {
            break;
        }

        let mut name_table_rva = unsafe { descriptor.Anonymous.OriginalFirstThunk };
        let address_table_rva = descriptor.FirstThunk;

        if name_table_rva == 0 {
            name_table_rva = address_table_rva;
        }

        let name = PCSTR::from_raw(name_ptr.unwrap());
        let name_table: Option<*const usize> = pe.rva_to_ptr(name_table_rva);
        let address_table: Option<*const *const u8> = pe.rva_to_ptr(address_table_rva);

        if name_table.is_none() || address_table.is_none() {
            return false;
        }

        if !load_imports_for_library(pe, name, address_table.unwrap(), name_table.unwrap()) {
            return false;
        }
    }

    return true;
}

unsafe fn load_executable_as_library(lib: &str) -> Option<Executable> {
    let module = load_library(lib);
    if module.is_none() {
        return None;
    }

    let pe_file = module.unwrap();

    let entry_point = pe_file.get_entry_point();
    if entry_point.is_none() {
        return None;
    }

    let loaded = load_imports(&pe_file);
    if !loaded {
        return None;
    }

    return Some(Executable {
        entry_point: entry_point.unwrap(),
        handle: pe_file,
    });
}

fn main() {
    let exe = unsafe {
        load_executable_as_library(
            "C:\\Users\\mauri\\source\\repos\\ConsoleApp\\x64\\Release\\ConsoleApp.exe",
        )
    };

    if exe.is_some() {
        (exe.unwrap().entry_point)();
    }
}
