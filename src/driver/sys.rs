use std::ffi::c_void;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicPtr, Ordering};
use windows_sys::Win32::Foundation::{HANDLE, HMODULE, LUID};
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleFileNameW, GetModuleHandleExW, GetProcAddress, LoadLibraryW,
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
};

#[link(name = "iphlpapi")]
extern "system" {
    pub fn ConvertInterfaceLuidToIndex(interface_luid: *const LUID, interface_index: *mut u32) -> u32;
}

pub type WintunAdapterHandle = *mut c_void;
pub type WintunSessionHandle = *mut c_void;

pub type FnWintunCreateAdapter = unsafe extern "system" fn(
    name: *const u16,
    tunnel_type: *const u16,
    requested_guid: *const c_void,
) -> WintunAdapterHandle;
pub type FnWintunOpenAdapter = unsafe extern "system" fn(name: *const u16) -> WintunAdapterHandle;
pub type FnWintunCloseAdapter = unsafe extern "system" fn(adapter: WintunAdapterHandle);
pub type FnWintunGetAdapterLUID = unsafe extern "system" fn(adapter: WintunAdapterHandle, luid: *mut LUID) -> u32;
pub type FnWintunStartSession = unsafe extern "system" fn(adapter: WintunAdapterHandle, capacity: u32) -> WintunSessionHandle;
pub type FnWintunEndSession = unsafe extern "system" fn(session: WintunSessionHandle);
pub type FnWintunGetReadWaitEvent = unsafe extern "system" fn(session: WintunSessionHandle) -> HANDLE;
pub type FnWintunReceivePacket =
    unsafe extern "system" fn(session: WintunSessionHandle, packet_size: *mut u32) -> *mut u8;
pub type FnWintunReleaseReceivePacket = unsafe extern "system" fn(session: WintunSessionHandle, packet: *const u8);
pub type FnWintunAllocateSendPacket =
    unsafe extern "system" fn(session: WintunSessionHandle, packet_size: u32) -> *mut u8;
pub type FnWintunSendPacket = unsafe extern "system" fn(session: WintunSessionHandle, packet: *const u8);

pub struct WintunLib {
    pub create_adapter: FnWintunCreateAdapter,
    pub open_adapter: FnWintunOpenAdapter,
    pub close_adapter: FnWintunCloseAdapter,
    pub get_adapter_luid: FnWintunGetAdapterLUID,
    pub start_session: FnWintunStartSession,
    pub end_session: FnWintunEndSession,
    pub get_read_wait_event: FnWintunGetReadWaitEvent,
    pub receive_packet: FnWintunReceivePacket,
    pub release_receive_packet: FnWintunReleaseReceivePacket,
    pub allocate_send_packet: FnWintunAllocateSendPacket,
    pub send_packet: FnWintunSendPacket,
}

static WINTUN_LIB: AtomicPtr<WintunLib> = AtomicPtr::new(std::ptr::null_mut());

fn own_module_dir() -> Option<PathBuf> {
    let mut h_mod: HMODULE = std::ptr::null_mut();
    let ok = unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            own_module_dir as *const u16,
            &mut h_mod,
        )
    };
    if ok == 0 || h_mod.is_null() {
        return None;
    }
    let mut buf = [0u16; 512];
    let len = unsafe { GetModuleFileNameW(h_mod, buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if len == 0 || len >= buf.len() {
        return None;
    }
    let path = PathBuf::from(std::ffi::OsString::from_wide(&buf[..len]));
    path.parent().map(|p| p.to_path_buf())
}

fn find_wintun_dll() -> Option<PathBuf> {
    if let Some(dir) = own_module_dir() {
        let sibling = dir.join("wintun.dll");
        if sibling.exists() && sibling.is_file() {
            return Some(sibling);
        }
    }

    let candidates = [
        PathBuf::from("wintun.dll"),
        PathBuf::from("./wintun.dll"),
        PathBuf::from("bin/wintun.dll"),
        PathBuf::from("assets/wintun.dll"),
        PathBuf::from("../assets/wintun.dll"),
        PathBuf::from("zeltun/assets/wintun.dll"),
        PathBuf::from(r"C:\ProgramData\BYP\wintun.dll"),
        PathBuf::from(r"C:\ProgramData\Zeltun\wintun.dll"),
    ];

    for c in &candidates {
        if c.exists() && c.is_file() {
            return Some(c.clone());
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let next_to_exe = dir.join("wintun.dll");
            if next_to_exe.exists() {
                return Some(next_to_exe);
            }
        }
    }

    None
}

impl WintunLib {
    pub fn get() -> Result<&'static WintunLib, String> {
        let ptr = WINTUN_LIB.load(Ordering::Acquire);
        if !ptr.is_null() {
            return Ok(unsafe { &*ptr });
        }

        let path = find_wintun_dll().ok_or_else(|| {
            "wintun.dll not found in current directory, exe directory, or ProgramData/Byptun/bin".to_string()
        })?;

        let mut wide_path: Vec<u16> = path.as_os_str().encode_wide().collect();
        wide_path.push(0);

        let h_mod = unsafe { LoadLibraryW(wide_path.as_ptr()) };
        if h_mod.is_null() {
            return Err(format!("Failed to LoadLibraryW({:?})", path));
        }

        macro_rules! get_proc {
            ($h:expr, $fn_type:ty, $name:expr) => {{
                let p = unsafe { GetProcAddress($h, concat!($name, "\0").as_ptr()) };
                if p.is_none() {
                    return Err(format!("Missing symbol in wintun.dll: {}", $name));
                }
                unsafe { std::mem::transmute::<_, $fn_type>(p.unwrap()) }
            }};
        }

        let lib = Box::new(WintunLib {
            create_adapter: get_proc!(h_mod, FnWintunCreateAdapter, "WintunCreateAdapter"),
            open_adapter: get_proc!(h_mod, FnWintunOpenAdapter, "WintunOpenAdapter"),
            close_adapter: get_proc!(h_mod, FnWintunCloseAdapter, "WintunCloseAdapter"),
            get_adapter_luid: get_proc!(h_mod, FnWintunGetAdapterLUID, "WintunGetAdapterLUID"),
            start_session: get_proc!(h_mod, FnWintunStartSession, "WintunStartSession"),
            end_session: get_proc!(h_mod, FnWintunEndSession, "WintunEndSession"),
            get_read_wait_event: get_proc!(h_mod, FnWintunGetReadWaitEvent, "WintunGetReadWaitEvent"),
            receive_packet: get_proc!(h_mod, FnWintunReceivePacket, "WintunReceivePacket"),
            release_receive_packet: get_proc!(
                h_mod,
                FnWintunReleaseReceivePacket,
                "WintunReleaseReceivePacket"
            ),
            allocate_send_packet: get_proc!(h_mod, FnWintunAllocateSendPacket, "WintunAllocateSendPacket"),
            send_packet: get_proc!(h_mod, FnWintunSendPacket, "WintunSendPacket"),
        });

        let raw = Box::into_raw(lib);
        if let Err(_) = WINTUN_LIB.compare_exchange(
            std::ptr::null_mut(),
            raw,
            Ordering::Release,
            Ordering::Acquire,
        ) {
            unsafe { drop(Box::from_raw(raw)) };
        }

        Ok(unsafe { &*WINTUN_LIB.load(Ordering::Acquire) })
    }
}
