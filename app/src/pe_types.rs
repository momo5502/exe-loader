#[cfg(target_pointer_width = "64")]
pub mod pe_types {
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
pub mod pe_types {
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

pub use pe_types::*;
