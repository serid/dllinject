use crate::bindings::{
    Windows::Win32::Foundation::HANDLE,
    Windows::Win32::Foundation::CloseHandle,
};

pub struct HandleResource(HANDLE);

impl HandleResource {
    /// # Safety
    /// `handle` should be owned by caller and should not be closed after being moved into `HandleResource`
    pub unsafe fn new(handle: HANDLE) -> Self {
        HandleResource(handle)
    }

    pub fn get(&self) -> HANDLE {
        self.0
    }
}

impl Drop for HandleResource {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}