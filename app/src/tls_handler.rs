use std::os::raw::c_void;
use std::sync::{LazyLock, RwLock};

type TlsCallback = Box<dyn Fn(u32) + Send + Sync + 'static>;

static mut CAN_EXECUTE_HANDLERS: bool = false;
static TLS_CALLBACKS: LazyLock<RwLock<Vec<TlsCallback>>> =
    LazyLock::new(|| RwLock::new(Vec::new()));

type ImageTlsCallback = unsafe extern "system" fn(*mut c_void, u32, *mut c_void);

#[unsafe(no_mangle)]
#[unsafe(link_section = ".CRT$XLB")]
pub static TLS_CALLBACK: ImageTlsCallback = tls_callback as ImageTlsCallback;

unsafe extern "system" fn tls_callback(
    _dll_handle: *mut c_void,
    reason: u32,
    _reserved: *mut c_void,
) {
    if !unsafe { CAN_EXECUTE_HANDLERS } {
        return;
    }

    let vec = TLS_CALLBACKS.read().unwrap();
    for f in vec.iter() {
        f(reason);
    }
}

pub fn register_tls_callback(callback: TlsCallback) {
    unsafe { CAN_EXECUTE_HANDLERS = true };

    let mut vec = TLS_CALLBACKS.write().unwrap();
    vec.push(callback);
}
