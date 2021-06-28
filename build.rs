fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    windows::build! {
        // Windows::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot,
        Windows::Win32::Foundation::HANDLE,
        Windows::Win32::Foundation::HINSTANCE,
        Windows::Win32::System::ProcessStatus::K32EnumProcesses,
        Windows::Win32::System::Threading::OpenProcess,
        Windows::Win32::Foundation::CloseHandle,
        Windows::Win32::System::ProcessStatus::K32EnumProcessModulesEx,
        Windows::Win32::System::ProcessStatus::LIST_MODULES_32BIT,
        Windows::Win32::System::ProcessStatus::LIST_MODULES_64BIT,
        Windows::Win32::System::ProcessStatus::K32GetModuleBaseNameW,
        Windows::Win32::System::Threading::CreateRemoteThread,
        Windows::Win32::System::Memory::VirtualFreeEx,
        Windows::Win32::System::Memory::VirtualAllocEx,
        Windows::Win32::System::LibraryLoader::LoadLibraryExW,
        Windows::Win32::System::LibraryLoader::GetProcAddress,
        Windows::Win32::System::LibraryLoader::GetModuleHandleW,
        Windows::Win32::System::Diagnostics::Debug::FlushInstructionCache,
        Windows::Win32::System::Diagnostics::Debug::WriteProcessMemory,
        Windows::Win32::System::Diagnostics::Debug::GetLastError,
        Windows::Win32::System::Diagnostics::Debug::SetLastError,
    }
    ;
}