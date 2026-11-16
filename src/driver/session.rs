use std::os::windows::ffi::OsStrExt;
use std::sync::Mutex;
use windows_sys::Win32::Foundation::{HANDLE, LUID};

use super::sys::{ConvertInterfaceLuidToIndex, WintunAdapterHandle, WintunLib, WintunSessionHandle};

pub struct WintunAdapter {
    handle: WintunAdapterHandle,
    name: String,
    if_index: u32,
}

unsafe impl Send for WintunAdapter {}
unsafe impl Sync for WintunAdapter {}

impl WintunAdapter {
    pub fn create_or_open(name: &str, tunnel_type: &str) -> Result<Self, String> {
        let lib = WintunLib::get()?;

        let mut name_u16: Vec<u16> = std::ffi::OsStr::new(name).encode_wide().collect();
        name_u16.push(0);

        let mut tunnel_u16: Vec<u16> = std::ffi::OsStr::new(tunnel_type).encode_wide().collect();
        tunnel_u16.push(0);

        // 1. Try to open existing
        let mut handle = unsafe { (lib.open_adapter)(name_u16.as_ptr()) };
        if handle.is_null() {
            // 2. Create if not found
            handle = unsafe { (lib.create_adapter)(name_u16.as_ptr(), tunnel_u16.as_ptr(), std::ptr::null()) };
        }

        if handle.is_null() {
            return Err(format!("Failed to create or open Wintun adapter '{}'", name));
        }

        // Query LUID and Convert to ifIndex
        let mut luid: LUID = unsafe { std::mem::zeroed() };
        let mut if_index = 0u32;
        if unsafe { (lib.get_adapter_luid)(handle, &mut luid) } != 0 {
            unsafe {
                let _ = ConvertInterfaceLuidToIndex(&luid, &mut if_index);
            }
        }

        Ok(Self {
            handle,
            name: name.to_string(),
            if_index,
        })
    }

    pub fn if_index(&self) -> u32 {
        self.if_index
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn start_session(&self, capacity: u32) -> Result<WintunSession, String> {
        let lib = WintunLib::get()?;
        let session = unsafe { (lib.start_session)(self.handle, capacity) };
        if session.is_null() {
            return Err("WintunStartSession failed".to_string());
        }
        let read_event = unsafe { (lib.get_read_wait_event)(session) };
        Ok(WintunSession {
            handle: session,
            read_event,
            send_mu: Mutex::new(()),
        })
    }

    pub fn close(&mut self) {
        if !self.handle.is_null() {
            if let Ok(lib) = WintunLib::get() {
                unsafe {
                    (lib.close_adapter)(self.handle);
                }
            }
            self.handle = std::ptr::null_mut();
        }
    }
}

impl Drop for WintunAdapter {
    fn drop(&mut self) {
        self.close();
    }
}

pub struct WintunSession {
    handle: WintunSessionHandle,
    read_event: HANDLE,
    send_mu: Mutex<()>,
}

unsafe impl Send for WintunSession {}
unsafe impl Sync for WintunSession {}

impl WintunSession {
    pub fn read_event(&self) -> HANDLE {
        self.read_event
    }

    pub fn receive_packet<'a>(&self) -> Option<&'a mut [u8]> {
        let lib = WintunLib::get().ok()?;
        let mut size = 0u32;
        let ptr = unsafe { (lib.receive_packet)(self.handle, &mut size) };
        if ptr.is_null() || size == 0 {
            None
        } else {
            Some(unsafe { std::slice::from_raw_parts_mut(ptr, size as usize) })
        }
    }

    pub fn release_receive_packet(&self, pkt: &[u8]) {
        if let Ok(lib) = WintunLib::get() {
            unsafe {
                (lib.release_receive_packet)(self.handle, pkt.as_ptr());
            }
        }
    }

    pub fn allocate_send_packet<'a>(&self, size: u32) -> Option<&'a mut [u8]> {
        let lib = WintunLib::get().ok()?;
        let ptr = unsafe { (lib.allocate_send_packet)(self.handle, size) };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { std::slice::from_raw_parts_mut(ptr, size as usize) })
        }
    }

    pub fn send_packet(&self, pkt: &[u8]) {
        if let Ok(lib) = WintunLib::get() {
            unsafe {
                (lib.send_packet)(self.handle, pkt.as_ptr());
            }
        }
    }

    pub fn inject_packet(&self, pkt: &[u8]) -> bool {
        let _guard = match self.send_mu.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(send_buf) = self.allocate_send_packet(pkt.len() as u32) {
            send_buf.copy_from_slice(pkt);
            self.send_packet(send_buf);
            true
        } else {
            false
        }
    }

    pub fn end(&mut self) {
        if !self.handle.is_null() {
            if let Ok(lib) = WintunLib::get() {
                unsafe {
                    (lib.end_session)(self.handle);
                }
            }
            self.handle = std::ptr::null_mut();
        }
    }
}

impl Drop for WintunSession {
    fn drop(&mut self) {
        self.end();
    }
}
