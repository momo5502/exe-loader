#![no_std]
#![no_main]

use core::ffi::c_void;

type HINSTANCE = *mut c_void;

const DLL_PROCESS_ATTACH: u32 = 1;

unsafe extern "system" {
    fn DisableThreadLibraryCalls(hmodule: HINSTANCE) -> i32;
}

#[unsafe(no_mangle)]
pub extern "system" fn _DllMainCRTStartup(
    hmodule: HINSTANCE,
    reason: u32,
    _reserved: *mut c_void,
) -> i32 {
    if reason == DLL_PROCESS_ATTACH {
        unsafe {
            DisableThreadLibraryCalls(hmodule);
        }
    }
    1
}

#[cfg(not(test))]
#[panic_handler]
fn panic_handler(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[repr(C)]
pub struct ImageTlsDirectory {
    start_address_of_raw_data: *const u8,
    end_address_of_raw_data: *const u8,
    address_of_index: *const u32,
    address_of_callbacks: *const usize,
    size_of_zero_fill: u32,
    characteristics: u32,
}

unsafe impl Sync for ImageTlsDirectory {}

const TLS_BUFFER_SIZE: usize = 256 * 0x1000;

#[unsafe(link_section = ".tls$BBB")]
#[unsafe(no_mangle)]
pub static mut _tls_buffer: [u8; TLS_BUFFER_SIZE] = [0; TLS_BUFFER_SIZE];

#[unsafe(no_mangle)]
pub static mut _tls_index: u32 = 0;

#[unsafe(no_mangle)]
pub static mut _tls_array: u32 = 0;

#[unsafe(link_section = ".tls$AAA")]
#[unsafe(no_mangle)]
pub static mut _tls_start: u8 = 0;

#[unsafe(link_section = ".tls$ZZZ")]
#[unsafe(no_mangle)]
pub static mut _tls_end: u8 = 0;

#[unsafe(link_section = ".CRT$XLA")]
#[unsafe(no_mangle)]
pub static __xl_a: usize = 0;

#[unsafe(link_section = ".CRT$XLZ")]
#[unsafe(no_mangle)]
pub static __xl_z: usize = 0;

#[unsafe(link_section = ".rdata$T")]
#[unsafe(no_mangle)]
pub static _tls_used: ImageTlsDirectory = ImageTlsDirectory {
    start_address_of_raw_data: &raw const _tls_start,
    end_address_of_raw_data: &raw const _tls_end,
    address_of_index: &raw const _tls_index,
    address_of_callbacks: unsafe { (&raw const __xl_a).offset(1) },
    size_of_zero_fill: 0,
    characteristics: 0,
};
