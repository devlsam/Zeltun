pub const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
pub const FNV_PRIME: u64 = 0x100000001b3;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteAction {
    Direct = 0,
    Proxy = 1,
    Drop = 2,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitMode {
    Global = 0,
    Include = 1,
    Exclude = 2,
}

impl From<u8> for SplitMode {
    fn from(v: u8) -> Self {
        match v {
            1 => SplitMode::Include,
            2 => SplitMode::Exclude,
            _ => SplitMode::Global,
        }
    }
}

#[inline(always)]
pub fn fnv1a_hash(data: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    for &b in data {
        hash ^= b as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

pub fn normalize_and_hash_app(app: &str) -> u64 {
    let trimmed = app.trim().trim_matches(|c| c == '"' || c == '\'' || c == '`');
    let trimmed = trimmed.rsplit(['\\', '/']).next().unwrap_or(trimmed).trim();
    if trimmed.is_empty() {
        return 0;
    }
    let mut lower = [0u8; 64];
    let mut len = 0;
    for &b in trimmed.as_bytes().iter().take(64) {
        lower[len] = b.to_ascii_lowercase();
        len += 1;
    }

    let is_exe = len >= 4 && &lower[len - 4..len] == b".exe";
    if !is_exe && len + 4 <= 64 {
        lower[len..len + 4].copy_from_slice(b".exe");
        len += 4;
    }

    fnv1a_hash(&lower[..len])
}

#[inline(always)]
pub fn is_private_ip(ip: [u8; 4]) -> bool {
    ip[0] == 0
        || ip[0] == 10
        || (ip[0] == 100 && (ip[1] >= 64 && ip[1] <= 127))
        || ip[0] == 127
        || (ip[0] == 169 && ip[1] == 254)
        || (ip[0] == 172 && (ip[1] >= 16 && ip[1] <= 31))
        || (ip[0] == 192 && ip[1] == 168)
        || (ip[0] == 198 && (ip[1] == 18 || ip[1] == 19))
        || ip[0] >= 224
}

#[inline(always)]
pub fn is_lan_ip(ip: [u8; 4]) -> bool {
    if ip[0] == 10 {
        if ip[1] == 10 && ip[2] == 34 {
            return false;
        }
        return true;
    }
    if ip[0] == 172 && (ip[1] >= 16 && ip[1] <= 31) {
        return true;
    }
    if ip[0] == 192 && ip[1] == 168 {
        return true;
    }
    if ip[0] == 169 && ip[1] == 254 {
        return true;
    }
    false
}

pub fn is_known_proxy(name: &str) -> bool {
    is_known_proxy_bytes(name.as_bytes())
}

pub fn is_known_proxy_bytes(bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    let mut lower = [0u8; 64];
    let len = bytes.len();
    for (dst, &src) in lower[..len].iter_mut().zip(bytes) {
        *dst = src.to_ascii_lowercase();
    }
    matches!(
        &lower[..len],
        b"byp.exe"
            | b"byptun.exe"
            | b"byptun-rs.exe"
            | b"zeltun.exe"
            | b"zeltun-rs.exe"
            | b"zeltun-cli.exe"
            | b"xray.exe"
            | b"v2ray.exe"
            | b"sing-box.exe"
            | b"clash.exe"
            | b"mihomo.exe"
            | b"hysteria.exe"
            | b"naive.exe"
            | b"nekoray.exe"
            | b"nekobox.exe"
            | b"hiddify.exe"
            | b"v2rayn.exe"
    )
}
