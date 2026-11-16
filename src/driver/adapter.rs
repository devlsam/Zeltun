pub mod detect {
    pub use super::super::adapter_detect::*;
}

pub use super::adapter_detect::*;

use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateUnicastIpAddressEntry, FreeMibTable, GetIfEntry2, GetUnicastIpAddressTable,
    InitializeUnicastIpAddressEntry, MIB_IF_ROW2, MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE,
};
use windows_sys::Win32::Networking::WinSock::AF_INET;

pub const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(Debug, Clone)]
pub struct PhysicalAdapterInfo {
    pub adapter_name: String,
    pub gateway: String,
    pub lan_ip: [u8; 4],
    pub if_index: u32,
    pub metric: u32,
}

pub fn assign_ip_to_adapter(if_index: u32, ip: [u8; 4], prefix_len: u8) -> Result<(), u32> {
    unsafe {
        let mut row: MIB_UNICASTIPADDRESS_ROW = std::mem::zeroed();
        InitializeUnicastIpAddressEntry(&mut row);
        row.InterfaceIndex = if_index;
        row.Address.si_family = AF_INET as u16;
        row.Address.Ipv4.sin_family = AF_INET as u16;
        row.Address.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip);
        row.OnLinkPrefixLength = prefix_len;
        row.DadState = 4; // IpDadStatePreferred = 4

        let ret = CreateUnicastIpAddressEntry(&row);
        if ret == 0 || ret == 5010 { // ERROR_OBJECT_ALREADY_EXISTS = 5010
            Ok(())
        } else {
            Err(ret)
        }
    }
}

pub fn is_virtual_adapter_name(name: &str) -> bool {
    let name_lower = name.to_lowercase();
    const VIRTUAL_KEYWORDS: &[&str] = &[
        "wintun", "tap", "tun", "vpn", "virtual", "vmware",
        "vbox", "virtualbox", "hyper-v", "vethernet", "wsl",
        "loopback", "pseudo", "teredo", "isatap", "wireguard",
    ];
    for kw in VIRTUAL_KEYWORDS {
        if name_lower.contains(kw) {
            return true;
        }
    }
    false
}

pub fn get_adapter_details(if_index: u32) -> Option<(String, String)> {
    unsafe {
        let mut if_row: MIB_IF_ROW2 = std::mem::zeroed();
        if_row.InterfaceIndex = if_index;
        if GetIfEntry2(&mut if_row) == 0 {
            let desc_len = if_row.Description.iter().position(|&c| c == 0).unwrap_or(if_row.Description.len());
            let desc = String::from_utf16_lossy(&if_row.Description[..desc_len]);
            let alias_len = if_row.Alias.iter().position(|&c| c == 0).unwrap_or(if_row.Alias.len());
            let alias = String::from_utf16_lossy(&if_row.Alias[..alias_len]);
            return Some((alias, desc));
        }
    }
    None
}

pub fn is_virtual_adapter(if_index: u32) -> bool {
    if if_index == 0 {
        return false;
    }
    if let Some((alias, desc)) = get_adapter_details(if_index) {
        return is_virtual_adapter_name(&alias) || is_virtual_adapter_name(&desc);
    }
    false
}

pub fn is_ip_assigned_to_system(target_ip: [u8; 4]) -> bool {
    let mut table_ptr: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    let res = unsafe { GetUnicastIpAddressTable(AF_INET as u16, &mut table_ptr) };
    if res == 0 && !table_ptr.is_null() {
        let count = unsafe { (*table_ptr).NumEntries };
        let entries = unsafe { std::slice::from_raw_parts((*table_ptr).Table.as_ptr(), count as usize) };
        let mut found = false;
        for entry in entries {
            let addr_u32 = unsafe { entry.Address.Ipv4.sin_addr.S_un.S_addr };
            if addr_u32.to_ne_bytes() == target_ip {
                found = true;
                break;
            }
        }
        unsafe { FreeMibTable(table_ptr as *const _) };
        return found;
    }
    false
}
