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
