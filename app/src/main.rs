use windows::Win32::System::Diagnostics::Debug::IMAGE_DIRECTORY_ENTRY_IMPORT;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA, LoadLibraryW};
use windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE;
use windows::core::{PCSTR, PCWSTR};

use windows::Win32::System::SystemServices::{IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR};

mod scoped_protection;
use scoped_protection::ScopedProtection;

mod pe_types;

mod pe_file;
use pe_file::PEFile;

use crate::pe_file::get_hmodule_from_handle_value;
use crate::tls_handler::register_tls_callback;

mod tls_handler;

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

    if main_tls_dir.AddressOfCallBacks != 0 {
        let mut tls_callback_count = 0;
        let source_callbacks = main_tls_dir.AddressOfCallBacks as *const usize;
        let target_callbacks = target_tls_dir.AddressOfCallBacks as *mut usize;

        loop {
            let current_index = tls_callback_count;
            tls_callback_count += 1;

            let callback = unsafe { *source_callbacks.add(current_index) };
            if callback == 0 {
                break;
            }
        }

        unsafe {
            let _s = ScopedProtection::new(
                target_callbacks,
                std::mem::size_of::<usize>() * tls_callback_count,
                PAGE_EXECUTE_READWRITE,
            );

            std::ptr::copy(
                source_callbacks,
                target_callbacks,
                std::mem::size_of::<usize>() * tls_callback_count,
            );
        }
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

fn setup_tls_callbacks(handle: windows::Win32::Foundation::HMODULE) {
    let handle_value = handle.get_handle_value();
    if handle_value.is_none() {
        return;
    }

    let value = handle_value.unwrap();

    let b = Box::new(move |reason: u32| {
        let h = unsafe { get_hmodule_from_handle_value(value) };
        h.call_tls_callbacks(reason);
    });

    register_tls_callback(b);

    const DLL_PROCESS_ATTACH: u32 = 1;
    handle.call_tls_callbacks(DLL_PROCESS_ATTACH);
}

fn main() {
    let exe = unsafe {
        load_executable_as_library(
            "C:\\Users\\mauri\\source\\repos\\ConsoleApp\\x64\\Release\\ConsoleApp.exe",
        )
    };

    let bin = exe.expect("bruh");
    //setup_tls_callbacks(bin.handle);
    (bin.entry_point)();
}
