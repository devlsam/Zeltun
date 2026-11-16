use std::os::windows::process::CommandExt;
use std::process::Command;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetUnicastIpAddressTable, MIB_UNICASTIPADDRESS_TABLE,
};
use windows_sys::Win32::Networking::WinSock::AF_INET;

use super::adapter::{get_adapter_details, is_virtual_adapter_name, PhysicalAdapterInfo, CREATE_NO_WINDOW};

pub fn find_interface_by_ip(target_ip: [u8; 4]) -> Option<u32> {
    let mut table_ptr: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    let res = unsafe { GetUnicastIpAddressTable(AF_INET as u16, &mut table_ptr) };
    if res == 0 && !table_ptr.is_null() {
        let count = unsafe { (*table_ptr).NumEntries };
        let entries = unsafe { std::slice::from_raw_parts((*table_ptr).Table.as_ptr(), count as usize) };
        let mut found = None;
        for entry in entries {
            let addr_u32 = unsafe { entry.Address.Ipv4.sin_addr.S_un.S_addr };
            if addr_u32.to_ne_bytes() == target_ip {
                found = Some(entry.InterfaceIndex);
                break;
            }
        }
        unsafe { FreeMibTable(table_ptr as *const _) };
        return found;
    }
    None
}

pub fn find_ip_by_interface(if_index: u32) -> Option<[u8; 4]> {
    let mut table_ptr: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    let res = unsafe { GetUnicastIpAddressTable(AF_INET as u16, &mut table_ptr) };
    if res == 0 && !table_ptr.is_null() {
        let count = unsafe { (*table_ptr).NumEntries };
        let entries = unsafe { std::slice::from_raw_parts((*table_ptr).Table.as_ptr(), count as usize) };
        let mut found = None;
        for entry in entries {
            if entry.InterfaceIndex == if_index {
                let addr_u32 = unsafe { entry.Address.Ipv4.sin_addr.S_un.S_addr };
                let ip = addr_u32.to_ne_bytes();
                if ip[0] != 127 && ip[0] != 0 && !(ip[0] == 169 && ip[1] == 254) {
                    found = Some(ip);
                    break;
                }
            }
        }
        unsafe { FreeMibTable(table_ptr as *const _) };
        return found;
    }
    None
}

pub fn detect_physical_adapter() -> PhysicalAdapterInfo {
    let mut candidates: Vec<PhysicalAdapterInfo> = Vec::new();

    if let Ok(output) = Command::new("route").args(&["print", "0.0.0.0"]).creation_flags(CREATE_NO_WINDOW).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 5 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
                let (gw, iface_str) = (fields[2], fields[3]);
                let metric = fields[4].parse::<u32>().unwrap_or(999);

                if gw == "On-link" || gw == "0.0.0.0" || gw.starts_with("127.")
                    || gw.starts_with("10.255.") || gw.starts_with("172.19.")
                    || gw.starts_with("198.18.") || gw.starts_with("198.19.") || gw.starts_with("169.254.")
                { continue; }

                if iface_str.starts_with("127.") || iface_str.starts_with("169.254.")
                    || iface_str.starts_with("198.18.") || iface_str.starts_with("198.19.")
                { continue; }

                let Ok(lan_ip_parsed) = iface_str.parse::<std::net::Ipv4Addr>() else { continue; };
                let lan_ip = lan_ip_parsed.octets();

                if let Some(if_idx) = find_interface_by_ip(lan_ip) {
                    let (alias, desc) = get_adapter_details(if_idx).unwrap_or(("Ethernet".to_string(), "".to_string()));
                    if is_virtual_adapter_name(&alias) || is_virtual_adapter_name(&desc) {
                        continue;
                    }
                    candidates.push(PhysicalAdapterInfo {
                        adapter_name: if !alias.is_empty() { alias } else { desc },
                        gateway: gw.to_string(),
                        lan_ip,
                        if_index: if_idx,
                        metric,
                    });
                }
            }
        }
    }

    if let Some(best) = candidates.into_iter().min_by_key(|c| c.metric) {
        return best;
    }

    PhysicalAdapterInfo {
        adapter_name: "Ethernet".to_string(),
        gateway: "192.168.1.1".to_string(),
        lan_ip: [192, 168, 1, 2],
        if_index: 0,
        metric: 25,
    }
}
