// #![warn(unused_unsafe)]
#![allow(unused_imports)]

use std::ffi::c_void;
use std::iter::repeat;
use std::mem;
use std::mem::MaybeUninit;
use std::mem::size_of;
use std::mem::transmute;
use std::ptr;
use std::slice;

use bindings::{
    // Windows::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot,
    Windows::Win32::Foundation::BOOL,
    Windows::Win32::Foundation::FARPROC,
    Windows::Win32::Foundation::HANDLE,
    Windows::Win32::Foundation::HINSTANCE,
    Windows::Win32::Foundation::PSTR,
    Windows::Win32::Foundation::PWSTR,
    Windows::Win32::System::Diagnostics::Debug::FlushInstructionCache,
    Windows::Win32::System::Diagnostics::Debug::WriteProcessMemory,
    Windows::Win32::System::LibraryLoader::GetModuleHandleW,
    Windows::Win32::System::LibraryLoader::GetProcAddress,
    Windows::Win32::System::LibraryLoader::LOAD_LIBRARY_FLAGS,
    Windows::Win32::System::LibraryLoader::LoadLibraryExW,
    Windows::Win32::System::Memory::MEM_COMMIT,
    Windows::Win32::System::Memory::MEM_RELEASE,
    Windows::Win32::System::Memory::MEM_RESERVE,
    Windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE,
    Windows::Win32::System::Memory::PAGE_READWRITE,
    Windows::Win32::System::Memory::VirtualAllocEx,
    Windows::Win32::System::Memory::VirtualFreeEx,
    Windows::Win32::System::ProcessStatus::K32EnumProcesses,
    Windows::Win32::System::ProcessStatus::K32EnumProcessModulesEx,
    Windows::Win32::System::ProcessStatus::K32GetModuleBaseNameW,
    Windows::Win32::System::ProcessStatus::LIST_MODULES_32BIT,
    Windows::Win32::System::ProcessStatus::LIST_MODULES_64BIT,
    Windows::Win32::System::SystemServices::LPTHREAD_START_ROUTINE,
    Windows::Win32::System::Threading::CreateRemoteThread,
    Windows::Win32::System::Threading::OpenProcess,
    Windows::Win32::System::Threading::PROCESS_CREATE_THREAD,
    Windows::Win32::System::Threading::PROCESS_QUERY_INFORMATION,
    Windows::Win32::System::Threading::PROCESS_VM_OPERATION,
    Windows::Win32::System::Threading::PROCESS_VM_READ,
    Windows::Win32::System::Threading::PROCESS_VM_WRITE,
    Windows::Win32::System::Threading::PROCESS_ALL_ACCESS,
    Windows::Win32::System::Diagnostics::Debug::GetLastError,
    Windows::Win32::System::Diagnostics::Debug::SetLastError,
};
use handle_resource::HandleResource;
use iterators::append_iterator::*;
use iterators::append_iterator::*;

use crate::Error::{GetProcAddressFailure, LoadLibraryFailure};
use crate::iterators::extend_iterator::Extend;
use crate::remote_buffer::RemoteBuffer;

mod bindings;
mod handle_resource;
mod iterators;
mod remote_buffer;

#[derive(Debug)]
pub enum Error {
    HandleIsNull,
    NoModules,
    LoadLibraryFailure,
    GetProcAddressFailure,
}

type MyResult<T> = Result<T, Error>;

pub fn vec_of_clones<T: Clone>(value: T, n: usize) -> Vec<T> {
    repeat(value).take(n).collect()
}

/// `syscall` should be a partially applied win32 function that outputs objects of type R into array pointed to by first argument,
/// receives array size in bytes in second argument,
/// outputs number of bytes written to address pointed to by third argument
/// and returns BOOL indicating whether or not it succeeded
///
/// `predicate` should be a function that compares old array size (arg 1), array size returned by syscall (arg 2) and updates size (arg 1) accordingly
/// return value determines whether the iteration should be ended (current array will be returned)
pub unsafe fn loop_base<R: Copy, F1: Fn(*mut R, u32, *mut u32) -> BOOL, F2: Fn(&mut usize, &usize) -> bool>(syscall: &F1, predicate: &F2) -> Box<[R]> {
    // Stores number of bytes written by previous request
    let mut objects_output_bytes = MaybeUninit::<u32>::uninit();
    let mut size = 1024;

    // Search for a suitable array size while also requesting objects
    repeat(()).find_map(|()| {
        // Allocate storage for results
        let mut objects = vec_of_clones(MaybeUninit::<R>::uninit(), size).into_boxed_slice();

        // Perform the request
        let ok = syscall(objects.as_mut_ptr() as *mut R, (objects.len() * size_of::<R>()) as u32, objects_output_bytes.as_mut_ptr());
        if !ok.as_bool() {
            panic!("err false");
        }

        let objects_output_bytes = unsafe { objects_output_bytes.assume_init() };
        let objects_output_length = objects_output_bytes as usize / size_of::<R>();

        if predicate(&mut size, &objects_output_length) {
            // Cut the array at `objects_output_bytes`
            let shrunk = objects.into_iter().take(objects_output_length).map(|v| unsafe { v.assume_init() }).collect::<Box<[R]>>();

            Some(shrunk)
        } else {
            None
        }
    }).unwrap()
}

/// Looping strategy one
pub unsafe fn loop1<R: Copy, F: Fn(*mut R, u32, *mut u32) -> BOOL>(func: &F) -> Box<[R]> {
    loop_base(func, &|old_size, new_size| {
        debug_assert!(*old_size >= *new_size);

        // If the array used was not large enough to fit all the results, retry the request with a larger array
        if old_size == new_size {
            *old_size *= 2;
            false
        } else {
            true
        }
    })
}

/// Looping strategy two
pub unsafe fn loop2<R: Copy, F: Fn(*mut R, u32, *mut u32) -> BOOL>(func: &F) -> Box<[R]> {
    loop_base(func, &|old_size, new_size| {
        // If recommended size is larger than size used, retry the request with larger array
        if *new_size as usize > *old_size * size_of::<R>() {
            *old_size = *new_size;
            false
        } else {
            true
        }
    })
}

type Utf16Unit = u16;

/// Looping stategy for syscalls returning UTF-16 strings
pub unsafe fn loop_str<F: Fn(*mut Utf16Unit, u32) -> u32>(func: &F) -> Box<[Utf16Unit]> {
    // String size in Utf16Unit units
    let mut size = 50;

    // Search for a suitable array size while also requesting objects
    repeat(()).find_map(|()| {
        // Allocate storage for results
        let mut objects = vec_of_clones(MaybeUninit::<Utf16Unit>::uninit(), size).into_boxed_slice();

        // Perform the request
        let bytes_copied = func(objects.as_mut_ptr() as *mut Utf16Unit, (objects.len() * size_of::<Utf16Unit>()) as u32);
        if bytes_copied == 0 {
            panic!("err 0");
        }

        // dbg!(bytes_copied);

        let units_copied = bytes_copied as usize / size_of::<Utf16Unit>();

        if units_copied < size {
            // Cut the array at `units_copied`
            let shrunk = objects.into_iter().take(units_copied).map(|v| unsafe { v.assume_init() }).collect::<Box<[Utf16Unit]>>();
            Some(shrunk)
        } else {
            // Lift array size and repeat
            size *= 2;
            None
        }
    }).unwrap()
}

pub fn get_process_ids() -> Box<[u32]> {
    let f = |p: *mut u32, n: u32, out: *mut u32| -> BOOL {
        unsafe { K32EnumProcesses(p, n, out) }
    };

    unsafe { loop1::<u32, _>(&f) }
}

pub fn get_process_modules(process: &HandleResource) -> Box<[HINSTANCE]> {
    let f = |p: *mut HINSTANCE, n: u32, out: *mut u32| -> BOOL {
        unsafe { K32EnumProcessModulesEx(process.get(), p, n, out, LIST_MODULES_32BIT | LIST_MODULES_64BIT) }
    };

    unsafe { loop2::<HINSTANCE, _>(&f) }
}

pub fn get_module_name(process: &HandleResource, module: HINSTANCE) -> Box<[Utf16Unit]> {
    let f = |p: *mut Utf16Unit, n: u32| -> u32 {
        unsafe { K32GetModuleBaseNameW(process.get(), module, PWSTR(p), n) }
    };

    unsafe { loop_str::<_>(&f) }
}

pub fn simple_open_process(id: u32) -> HandleResource {
    unsafe { HandleResource::new(OpenProcess(PROCESS_QUERY_INFORMATION, false, id)) }
}

pub fn get_process_name(process: &HandleResource) -> MyResult<String> {
    if process.get().is_null() {
        return Err(Error::HandleIsNull);
    }

    let modules = get_process_modules(process);

    if modules.len() == 0 {
        return Err(Error::NoModules);
    }

    let name = get_module_name(process, modules[0]);

    let name = String::from_utf16(&name).unwrap();

    Ok(name)
}

pub fn find_process_by_name(name: &str) -> impl Iterator<Item=HandleResource> + '_ {
    println!("Searching for \"{}\"", name);

    let process_access_rights = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD;
    let process_access_rights = PROCESS_ALL_ACCESS;

    let processes = get_process_ids();

    processes.into_vec().into_iter().filter_map(move |id| {
        let handle = unsafe { HandleResource::new(OpenProcess(process_access_rights, false, id)) };
        get_process_name(&handle).ok().and_then(|name_i| {
            name_i.contains(name).then(|| handle)
        })
    })
}

/// MSDN says that GetCurrentProcess returns (HANDLE)-1, tho it might change in future
pub fn get_current_process() -> HandleResource {
    unsafe { HandleResource::new(HANDLE(-1)) }
}

pub fn funny_function(s: &[u16]) -> &[u8] {
    unsafe { slice::from_raw_parts(s.as_ptr() as *const u8, s.len() * 2) }
}

pub fn to_null_terminated_utf16(string: &str) -> Box<[Utf16Unit]> {
    string.encode_utf16().extend(0).collect()
}

pub fn to_null_terminated_ascii(string: &str) -> Box<[u8]> {
    assert!(string.is_ascii());
    string.as_bytes().iter().copied().extend(0).collect()
}

pub fn load_library(filename: &str) -> HINSTANCE {
    unsafe { LoadLibraryExW(PWSTR(to_null_terminated_utf16(filename).as_mut_ptr()), HANDLE::NULL, LOAD_LIBRARY_FLAGS(0)) }
}

pub fn get_proc_address(module: HINSTANCE, proc_name: &str) -> Option<FARPROC> {
    unsafe { GetProcAddress(module, PSTR(to_null_terminated_ascii(proc_name).as_mut_ptr())) }
}

pub fn get_module_handle(module_name: &str) -> HINSTANCE {
    unsafe { GetModuleHandleW(PWSTR(to_null_terminated_utf16(module_name).as_mut_ptr())) }
}

pub fn allocate_in_remote_process(process: &HandleResource, size: usize, executable_eh: bool) -> *mut c_void {
    let page_protection_flags = if executable_eh {
        PAGE_EXECUTE_READWRITE
    } else {
        PAGE_READWRITE
    };
    unsafe { VirtualAllocEx(process.get(), ptr::null_mut(), size, MEM_COMMIT | MEM_RESERVE, page_protection_flags) }
}

pub fn dealloc(process: &HandleResource, ptr: *mut c_void) -> Result<(), ()> {
    unsafe { VirtualFreeEx(process.get(), ptr, 0, MEM_RELEASE) }.as_bool().then(|| ()).ok_or(())
}

pub fn flush_instruction_cache(process: &HandleResource, ptr: *mut c_void, size: usize) -> Result<(), ()> {
    unsafe { FlushInstructionCache(process.get(), ptr, size) }.as_bool().then(|| ()).ok_or(())
}

pub fn write_process_memory(process: &HandleResource, base_address: *mut c_void, buffer: *const c_void, size: usize) -> Result<usize, ()> {
    let mut out = MaybeUninit::<usize>::new(0);
    let r = unsafe { WriteProcessMemory(process.get(), base_address, buffer, size, /*out.as_mut_ptr()*/ptr::null_mut()) };
    r.as_bool().then(|| unsafe { out.assume_init() }).ok_or(())
}

pub fn create_remote_thread(process: &HandleResource, start_address: FARPROC, parameter: *mut c_void) -> (HandleResource, u32) {
    assert_eq!(size_of::<FARPROC>(), size_of::<LPTHREAD_START_ROUTINE>());
    let mut out = MaybeUninit::<u32>::uninit();
    unsafe {
        let handle = CreateRemoteThread(process.get(), ptr::null_mut(), 0, Some(transmute::<_, LPTHREAD_START_ROUTINE>(start_address)), parameter, 0, out.as_mut_ptr());
        (HandleResource::new(handle), out.assume_init())
    }
}

type InjMainFunc = extern "C" fn();

pub fn inject_local(dllname: &str) -> MyResult<()> {
    let dll = load_library(dllname);
    (!dll.is_null()).then(|| ()).ok_or(LoadLibraryFailure)?;

    let inj_main = get_proc_address(dll, "InjMain").ok_or(GetProcAddressFailure)?;
    // println!("'InjMain' proc address: {:?}", inj_main as usize);

    unsafe { transmute::<_, InjMainFunc>(inj_main)() };
    Ok(())
}

// /// not working
// pub fn inject(target: &HandleResource, dllname: &str) -> MyResult<()> {
//     let kernel32 = get_module_handle("Kernel32.dll");
//     (!kernel32.is_null()).then(|| ()).ok_or(LoadLibraryFailure)?;
//
//     let load_library_w = get_proc_address(kernel32, "LoadLibraryW").ok_or(GetProcAddressFailure)?;
//     println!("'LoadLibraryW' proc address: {:?}", load_library_w as usize);
//     let get_proc_address_func = get_proc_address(kernel32, "GetProcAddress").ok_or(GetProcAddressFailure)?;
//     println!("'GetProcAddress' proc address: {:?}", get_proc_address_func as usize);
//
//     // Bootstrap program to be written to remote process and subsequently executed
//     // void *dll = LoadLibraryW(dllname);
//     // void *inj_main = GetProcAddress(dll, "InjMain");
//     // see bootstrap.cpp for full code
//
//     let dllname_str = dllname;
//     assert!(dllname_str.is_ascii());
//     let dllname_remote = RemoteBuffer::new(target, dllname_str.as_bytes(), false);
//
//     let inj_main_str = "InjMain";
//     assert!(inj_main_str.is_ascii());
//     let inj_main_remote = RemoteBuffer::new(target, inj_main_str.as_bytes(), false);
//
//     let args: [*mut c_void; 4] = [
//         load_library_w as *mut c_void,
//         get_proc_address_func as *mut c_void,
//         dllname_remote.get(),
//         inj_main_remote.get()
//     ];
//     let args_b: [u8; 32] = unsafe { mem::transmute(args) };
//
//     let args_remote = RemoteBuffer::new(target, &args_b, false);
//
//     let bootstrap_bytes: [u8; 34] = [0x53, 0x48, 0x83, 0xec, 0x20, 0x48, 0x89, 0xcb, 0x48, 0x8b, 0x49, 0x10, 0xff, 0x13, 0x48, 0x8b, 0x53, 0x18, 0x48, 0x89, 0xc1, 0xff, 0x53, 0x08, 0xff, 0xd0, 0x31, 0xc0, 0x48, 0x83, 0xc4, 0x20, 0x5b, 0xc3];
//     let bootstrap_remote = RemoteBuffer::new(target, &bootstrap_bytes, true);
//     bootstrap_remote.flush_instruction_cache();
//
//     let (thread, thread_id) = create_remote_thread(target, bootstrap_remote.get(), args_remote.get());
//     assert!(!thread.get().is_null());
//
//     mem::drop(dllname_remote);
//     mem::drop(inj_main_remote);
//     mem::drop(args_remote);
//     mem::drop(bootstrap_remote);
//
//     Ok(())
// }

pub fn inject_v2(target: &HandleResource, dllname: &str) -> MyResult<()> {
    let kernel32 = get_module_handle("Kernel32.dll");
    (!kernel32.is_null()).then(|| ()).ok_or(LoadLibraryFailure)?;

    let load_library_w = get_proc_address(kernel32, "LoadLibraryW").ok_or(GetProcAddressFailure)?;
    println!("'LoadLibraryW' proc address: {:?}", load_library_w as usize);

    let dllname_utf16 = to_null_terminated_utf16(dllname);
    let dllname_remote = RemoteBuffer::new(target, funny_function(&dllname_utf16), false);

    // println!("{}", String::from_utf16(&dllname_utf16).unwrap());

    let (thread, thread_id) = create_remote_thread(target, load_library_w, dllname_remote.get());
    assert!(!thread.get().is_null());
    println!("id: {}", thread_id);

    unsafe { SetLastError(0) };
    let err = unsafe { GetLastError() };
    assert!(err.0 == 0);

    Ok(())
}

pub fn inject_v3(target: &HandleResource, dllname: &str) -> MyResult<()> {
    let kernel32 = get_module_handle("Kernel32.dll");
    (!kernel32.is_null()).then(|| ()).ok_or(LoadLibraryFailure)?;

    let load_library_w = get_proc_address(kernel32, "LoadLibraryW").ok_or(GetProcAddressFailure)?;
    println!("'LoadLibraryW' proc address: {:?}", load_library_w as usize);

    let dllname_utf16 = to_null_terminated_utf16(dllname);

    let size = dllname_utf16.len() * size_of::<u16>();
    let remote_ptr = allocate_in_remote_process(target, size, true);
    assert!(!remote_ptr.is_null());
    write_process_memory(target, remote_ptr, dllname_utf16.as_ptr() as *const c_void, size).unwrap();

    let (thread, thread_id) = create_remote_thread(target, load_library_w, remote_ptr);
    assert!(!thread.get().is_null());
    println!("id: {}", thread_id);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a() {
        let numbers = vec_of_clones(10, 5);
        assert_eq!(vec![10, 10, 10, 10, 10], numbers);
    }

    #[test]
    fn b() {
        let iter = vec![1, 2, 3].into_iter();
        let mut appended_iter = iter.append(10);
        assert_eq!(appended_iter.next(), Some(10));
        assert_eq!(appended_iter.next(), Some(1));
        assert_eq!(appended_iter.next(), Some(2));
        assert_eq!(appended_iter.next(), Some(3));
        assert_eq!(appended_iter.next(), None);
    }

    #[test]
    fn c() {
        let iter = vec![1, 2, 3].into_iter();
        let mut appended_iter = iter.extend(10);
        assert_eq!(appended_iter.next(), Some(1));
        assert_eq!(appended_iter.next(), Some(2));
        assert_eq!(appended_iter.next(), Some(3));
        assert_eq!(appended_iter.next(), Some(10));
        assert_eq!(appended_iter.next(), None);
    }
}