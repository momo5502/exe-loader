use windows::Win32::System::{
    Diagnostics::Debug::{IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY, IMAGE_DIRECTORY_ENTRY_TLS},
    SystemServices::IMAGE_DOS_HEADER,
};

use crate::pe_types;

pub trait PEFile {
    fn get_base_address(&self) -> Option<*const u8>;

    fn get_handle_value(&self) -> Option<usize> {
        let base_address = self.get_base_address();
        if base_address.is_none() {
            return None;
        }

        let base_value = base_address.unwrap();
        let value: usize = unsafe { std::mem::transmute(base_value) };

        return Some(value);
    }

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

    fn call_tls_callbacks(&self, reason: u32) -> bool {
        let base_address = self.get_base_address();
        let tls_dir = self.get_tls_dir();

        if base_address.is_none() || tls_dir.is_none() {
            return false;
        }

        let base = base_address.unwrap();
        let callbacks = tls_dir.unwrap().AddressOfCallBacks as *const usize;

        if callbacks.is_null() {
            return false;
        }

        let mut index = 0;
        loop {
            let current_index = index;
            index += 1;

            let callback = unsafe { *callbacks.add(current_index) };
            if callback == 0 {
                break;
            }

            let tls_callback: fn(base: *const u8, reason: usize, reserved: usize) =
                unsafe { std::mem::transmute(callback) };

            tls_callback(base, reason as usize, 0);
        }

        return true;
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

pub fn get_hmodule_from_handle_value(value: usize) -> windows::Win32::Foundation::HMODULE {
    let handle: *mut core::ffi::c_void = unsafe { std::mem::transmute(value) };
    return windows::Win32::Foundation::HMODULE(handle);
}
