use windows::Win32::System::Diagnostics::Debug::{
    IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
};
use windows::Win32::System::LibraryLoader::LoadLibraryW;
use windows::core::PCWSTR;

use windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;

fn to_wide_string(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn analyze_library(lib: &str) {
    let wide_path = to_wide_string(lib);

    unsafe {
        let handle = LoadLibraryW(PCWSTR::from_raw(wide_path.as_ptr()));

        if handle.is_err() {
            println!("Failed to load library: {}", handle.err().unwrap());
            return;
        }

        println!("Successfully loaded: {}", lib);

        let base_address = handle.unwrap().0 as *const u8;

        let dos_header = base_address as *const IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != 0x5A4D {
            println!("Invalid DOS header");
            return;
        }

        let nt_headers =
            base_address.offset((*dos_header).e_lfanew as isize) as *const IMAGE_NT_HEADERS64;

        if (*nt_headers).Signature != 0x4550 {
            println!("Invalid PE signature");
            return;
        }

        let file_header = &(*nt_headers).FileHeader;
        let optional_header = &(*nt_headers).OptionalHeader;

        println!("\nPE Header Information:");
        println!("Machine: 0x{:X}", file_header.Machine.0);
        println!("Number of sections: {}", file_header.NumberOfSections);
        println!("Size of image: 0x{:X}", optional_header.SizeOfImage);
        println!("Entry point: 0x{:X}", optional_header.AddressOfEntryPoint);

        let image_base = optional_header.ImageBase;
        println!("Image base: 0x{:X}", image_base);

        let section_header = (nt_headers as *const u8)
            .offset(std::mem::size_of::<IMAGE_NT_HEADERS64>() as isize)
            as *const IMAGE_SECTION_HEADER;

        println!("\nSections:");
        for i in 0..file_header.NumberOfSections {
            let section = &*section_header.offset(i as isize);
            let name = std::str::from_utf8_unchecked(&section.Name).trim_end_matches('\0');
            println!(
                "  {}: VA=0x{:X}, Size=0x{:X}",
                name, section.VirtualAddress, section.Misc.VirtualSize
            );
        }
    }
}

fn main() {
    analyze_library("ntdll.dll");
}
