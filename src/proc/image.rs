use std::sync::Mutex;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use super::cache::{NAME_MAX_LEN, PROC_CACHE_SETS, PROC_CACHE_WAYS, ProcCacheSlot};

pub fn get_process_image_internal(
    proc_cache: &Mutex<[[ProcCacheSlot; PROC_CACHE_WAYS]; PROC_CACHE_SETS]>,
    pid: u32,
    now_sec: u32,
) -> Option<([u8; NAME_MAX_LEN], usize)> {
    if pid == 0 || pid == 4 {
        let mut name = [0u8; NAME_MAX_LEN];
        let s = b"system";
        name[..s.len()].copy_from_slice(s);
        return Some((name, s.len()));
    }

    let set_idx = ((pid >> 2) & ((PROC_CACHE_SETS - 1) as u32)) as usize;

    // 1. Fast read from 4-Way associative cache
    {
        let cache = proc_cache.lock().unwrap();
        for i in 0..PROC_CACHE_WAYS {
            let slot = &cache[set_idx][i];
            if slot.pid == pid && (now_sec.saturating_sub(slot.cached_secs)) < 30 {
                return Some((slot.name, slot.name_len as usize));
            }
        }
    }

    // 2. Query Windows Kernel
    let mut h_proc = unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
    };
    if h_proc.is_null() {
        h_proc = unsafe {
            OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid)
        };
        if h_proc.is_null() {
            return None;
        }
    }

    let mut path_buf = [0u16; 520];
    let mut path_size = path_buf.len() as u32;

    let ret = unsafe {
        QueryFullProcessImageNameW(h_proc, 0, path_buf.as_mut_ptr(), &mut path_size)
    };
    unsafe { CloseHandle(h_proc) };

    if ret == 0 || path_size == 0 {
        return None;
    }

    // Extract filename from UTF-16 path and convert to lowercase ASCII
    let full_path = &path_buf[..path_size as usize];
    let last_slash = full_path
        .iter()
        .rposition(|&c| c == b'\\' as u16 || c == b'/' as u16)
        .map(|idx| idx + 1)
        .unwrap_or(0);
    let filename_u16 = &full_path[last_slash..];

    let mut name = [0u8; NAME_MAX_LEN];
    let mut len = 0;
    for &ch in filename_u16.iter().take(NAME_MAX_LEN) {
        let b = if ch < 128 {
            (ch as u8).to_ascii_lowercase()
        } else {
            b'?'
        };
        name[len] = b;
        len += 1;
    }

    // 3. Write into 4-Way associative cache
    {
        let mut cache = proc_cache.lock().unwrap();
        let mut target_way = None;
        let mut oldest_way = 0;
        let mut oldest_secs = u32::MAX;

        for i in 0..PROC_CACHE_WAYS {
            let slot = &cache[set_idx][i];
            if slot.pid == pid || slot.pid == 0 || now_sec.saturating_sub(slot.cached_secs) >= 30 {
                target_way = Some(i);
                break;
            }
            if slot.cached_secs < oldest_secs {
                oldest_secs = slot.cached_secs;
                oldest_way = i;
            }
        }

        let way = target_way.unwrap_or(oldest_way);
        cache[set_idx][way] = ProcCacheSlot {
            pid,
            name_len: len as u8,
            name,
            cached_secs: now_sec,
        };
    }

    Some((name, len))
}
