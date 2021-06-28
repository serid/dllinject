use std::ffi::c_void;

use crate::{allocate_in_remote_process, dealloc, flush_instruction_cache, write_process_memory};
use crate::handle_resource::HandleResource;

pub struct RemoteBuffer<'target> {
    target: &'target HandleResource,
    ptr: *mut c_void,
    size: usize,
}

impl RemoteBuffer<'_> {
    pub fn new<'target>(target: &'target HandleResource, data: &[u8], executable_eh: bool) -> RemoteBuffer<'target> {
        let size = data.len();
        let remote_ptr = allocate_in_remote_process(target, size, executable_eh);
        assert!(!remote_ptr.is_null());
        write_process_memory(target, remote_ptr, data.as_ptr() as *const c_void, size).unwrap();
        RemoteBuffer {
            target,
            ptr: remote_ptr,
            size,
        }
    }

    pub fn flush_instruction_cache(&self) {
        flush_instruction_cache(self.target, self.ptr, self.size).unwrap();
    }

    pub fn get(&self) -> *mut c_void {
        self.ptr
    }
}

impl Drop for RemoteBuffer<'_> {
    fn drop(&mut self) {
        dealloc(self.target, self.ptr).unwrap();
    }
}