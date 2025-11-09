use windows::Win32::System::Diagnostics::Debug::{
    IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY, IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_TLS,
};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA, LoadLibraryW};
use windows::Win32::System::Memory::{
    PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, VirtualProtect,
};
use windows::core::{PCSTR, PCWSTR};

use windows::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR,
};

#[cfg(target_pointer_width = "64")]
mod pe_types {
    use windows::Win32::System::{
        Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_OPTIONAL_HEADER64},
        SystemServices::IMAGE_TLS_DIRECTORY64,
    };

    pub type ImageNtHeaders = IMAGE_NT_HEADERS64;
    pub type ImageOptionalHeader = IMAGE_OPTIONAL_HEADER64;
    pub type ImageTlsDirectory = IMAGE_TLS_DIRECTORY64;

    pub const IMAGE_ORDINAL_FLAG: usize = 0x8000000000000000;

    fn read_gs_qword(offset: u32) -> u64 {
        let value: u64;
        unsafe {
            core::arch::asm!(
                "mov {}, gs:[{:e}]",
                out(reg) value,
                in(reg) offset,
                options(nostack, preserves_flags)
            );
        }

        return value;
    }

    pub fn get_tls_vector() -> *const *mut u8 {
        return read_gs_qword(0x58) as *const *mut u8;
    }
}

#[cfg(target_pointer_width = "32")]
mod pe_types {
    use windows::Win32::System::{
        Diagnostics::Debug::{IMAGE_NT_HEADERS32, IMAGE_OPTIONAL_HEADER32},
        SystemServices::IMAGE_TLS_DIRECTORY32,
    };

    pub type ImageNtHeaders = IMAGE_NT_HEADERS32;
    pub type ImageOptionalHeader = IMAGE_OPTIONAL_HEADER32;
    pub type ImageTlsDirectory = IMAGE_TLS_DIRECTORY32;

    pub const IMAGE_ORDINAL_FLAG: usize = 0x80000000;

    fn read_fs_dword(offset: u32) -> u32 {
        let value: u32;
        unsafe {
            core::arch::asm!(
                "mov {}, fs:[{:e}]",
                out(reg) value,
                in(reg) offset,
                options(nostack, preserves_flags)
            );
        }

        return value;
    }

    pub fn get_tls_vector() -> *const *mut u8 {
        return read_fs_dword(0x2C) as *const *mut u8;
    }
}

fn get_tls_data(tls_index: u32) -> *mut u8 {
    let tls_vector = pe_types::get_tls_vector();
    return unsafe { *tls_vector.add(tls_index as usize) };
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

    fn get_directory_entry(&self, entry: IMAGE_DIRECTORY_ENTRY) -> Option<&IMAGE_DATA_DIRECTORY> {
        let optional_header = self.get_optional_header();
        return Some(&optional_header?.DataDirectory[entry.0 as usize]);
    }

    fn get_tls_dir(&self) -> Option<&pe_types::ImageTlsDirectory> {
        let entry = self.get_directory_entry(IMAGE_DIRECTORY_ENTRY_TLS);

        if entry?.VirtualAddress == 0 || entry?.Size == 0 {
            return None;
        }

        let tls_dir: Option<*const pe_types::ImageTlsDirectory> =
            self.rva_to_ptr(entry?.VirtualAddress);
        if tls_dir.is_none() {
            return None;
        }

        return Some(unsafe { &*tls_dir.unwrap() });
    }

    fn call_tls_callbacks(&self, attach: bool) {
        let base_address = self.get_base_address();
        let tls_dir = self.get_tls_dir();

        if base_address.is_none() || tls_dir.is_none() {
            return;
        }

        let reason = if attach { 2 } else { 3 };

        let base = base_address.unwrap();
        let callbacks = tls_dir.unwrap().AddressOfCallBacks as *const usize;

        if callbacks == core::ptr::null() {
            return;
        }

        let mut index = 0;
        loop {
            let current_index = index;
            index += 1;

            let callback = unsafe { *callbacks.add(current_index) };
            if callback == 0 {
                break;
            }

            let tls_callback: fn(base: *const u8, reason: u8, reserved: usize) =
                unsafe { std::mem::transmute(callback) };

            tls_callback(base, reason, 0);
        }
    }
}

pub struct ScopedProtection {
    protected: bool,
    size: usize,
    address: *const core::ffi::c_void,
    old_protection: PAGE_PROTECTION_FLAGS,
}

impl ScopedProtection {
    unsafe fn new<T>(address: *const T, size: usize, protection: PAGE_PROTECTION_FLAGS) -> Self {
        let mut scope = Self {
            protected: false,
            size,
            address: address as *const core::ffi::c_void,
            old_protection: PAGE_EXECUTE_READWRITE,
        };

        let res = unsafe {
            VirtualProtect(
                scope.address,
                scope.size,
                protection,
                &mut scope.old_protection,
            )
        };
        scope.protected = res.is_ok();

        return scope;
    }
}

impl Drop for ScopedProtection {
    fn drop(&mut self) {
        if !self.protected {
            return;
        }

        self.protected = false;
        let mut old_protect = PAGE_EXECUTE_READWRITE;

        let res = unsafe {
            VirtualProtect(
                self.address,
                self.size,
                self.old_protection,
                &mut old_protect,
            )
        };

        res.expect("Reprotection must succeed");
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

        unsafe {
            let _s = ScopedProtection::new(
                address_table_entry_ptr,
                std::mem::size_of::<usize>(),
                PAGE_EXECUTE_READWRITE,
            );
            *(address_table_entry_ptr as *mut *const u8) = function_ptr
        };
    }

    return true;
}

fn load_tls_dll() -> Option<windows::Win32::Foundation::HMODULE> {
    // TODO: Fix
    return load_library("C:\\Users\\mauri\\Desktop\\testicles\\target\\release\\tls_lib.dll");
}

fn get_tls_size(tls_dir: &pe_types::ImageTlsDirectory) -> usize {
    return (tls_dir.EndAddressOfRawData - tls_dir.StartAddressOfRawData) as usize;
}

fn load_tls<T: PEFile>(pe: &T) -> bool {
    let tls_dir = pe.get_tls_dir();
    if tls_dir.is_none() {
        return true;
    }

    let tls_dll = load_tls_dll();
    if tls_dll.is_none() {
        return false;
    }

    let dll = tls_dll.unwrap();
    let dll_tls_dir = dll.get_tls_dir();
    if dll_tls_dir.is_none() {
        return false;
    }

    let main_tls_dir = tls_dir.unwrap();
    let target_tls_dir = dll_tls_dir.unwrap();

    let main_dir_size = get_tls_size(&main_tls_dir);
    let target_dir_size = get_tls_size(&target_tls_dir);

    // Not enough space, throw error?
    if main_dir_size > target_dir_size {
        return false;
    }

    if main_tls_dir.AddressOfIndex == 0 {
        return true;
    }

    let tls_index;
    let main_index_ptr = main_tls_dir.AddressOfIndex as *mut u32;
    let target_index_ptr = target_tls_dir.AddressOfIndex as *const u32;

    unsafe {
        let _s = ScopedProtection::new(
            main_index_ptr,
            std::mem::size_of::<u32>(),
            PAGE_EXECUTE_READWRITE,
        );
        tls_index = *target_index_ptr;
        *main_index_ptr = tls_index;
    }

    let main_tls_data = main_tls_dir.StartAddressOfRawData as *const u8;
    let target_tls_data = target_tls_dir.StartAddressOfRawData as *mut u8;

    if main_tls_dir.StartAddressOfRawData == 0 {
        return true;
    }

    let current_thread_data = get_tls_data(tls_index);

    unsafe {
        let _s = ScopedProtection::new(target_tls_data, main_dir_size, PAGE_EXECUTE_READWRITE);
        std::ptr::copy(main_tls_data, target_tls_data, main_dir_size);
        std::ptr::copy(main_tls_data, current_thread_data, main_dir_size);
    }

    return true;
}

fn load_imports<T: PEFile>(pe: &T) -> bool {
    let base_address = pe.get_base_address();
    let import_directory = pe.get_directory_entry(IMAGE_DIRECTORY_ENTRY_IMPORT);

    if base_address.is_none() || import_directory.is_none() {
        return false;
    }

    let descriptor_ptr: Option<*const IMAGE_IMPORT_DESCRIPTOR> =
        pe.rva_to_ptr(import_directory.unwrap().VirtualAddress);

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

    if !load_imports(&pe_file) || !load_tls(&pe_file) {
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

    let bin = exe.expect("bruh");

    println!("Spawning thread...");

    let computation = std::thread::spawn(|| {
        println!("Hello from thread!");
    });

    let _ = computation.join();

    bin.handle.call_tls_callbacks(true);

    (bin.entry_point)();
}
