fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    windows::build! {
        Windows::Win32::Foundation::HWND,
        Windows::Win32::Foundation::HINSTANCE,
        Windows::Win32::Foundation::BOOL,
        Windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH,
        Windows::Win32::UI::WindowsAndMessaging::MessageBoxA,
    }
    ;
}