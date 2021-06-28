use std::ffi::c_void;

use bindings::{
    Windows::Win32::Foundation::BOOL,
    Windows::Win32::Foundation::HWND,
    Windows::Win32::Foundation::HINSTANCE,
    Windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH,
    Windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_STYLE,
    Windows::Win32::UI::WindowsAndMessaging::MessageBoxA,
};

mod bindings;

#[no_mangle]
pub extern "C" fn InjMain() {
    unsafe { MessageBoxA(HWND::NULL, "Funny text", "Funny", MESSAGEBOX_STYLE(0)) };
}

#[no_mangle]
pub extern "C" fn DllMain(instance: HINSTANCE, reason: u32, reserved: *mut c_void) -> BOOL {
    if reason == DLL_PROCESS_ATTACH || true {
        unsafe { MessageBoxA(HWND::NULL, "Funny text", "Funny", MESSAGEBOX_STYLE(0)) };
    }
    BOOL(1)
}