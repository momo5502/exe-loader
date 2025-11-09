use windows::Win32::System::Memory::{
    PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, VirtualProtect,
};

pub struct ScopedProtection {
    protected: bool,
    size: usize,
    address: *const core::ffi::c_void,
    old_protection: PAGE_PROTECTION_FLAGS,
}

impl ScopedProtection {
    pub unsafe fn new<T>(
        address: *const T,
        size: usize,
        protection: PAGE_PROTECTION_FLAGS,
    ) -> Self {
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
