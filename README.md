# Zeltun

Zero overhead, native speed, split tunneling.

A lightweight Windows Wintun TUN engine in Rust that turns any SOCKS5 proxy into a fast per-app split tunnel (`zeltun.dll` + `zeltun-rs.exe`).

## Build

Requires Rust (`x86_64-pc-windows-msvc`).

```bash
git clone https://github.com/devlsam/Zeltun.git
cd Zeltun
cargo build --release
```

Outputs are in `target/release/`:
- `zeltun.dll`
- `zeltun-rs.exe`

Place `assets/wintun.dll` next to `zeltun.dll` (or `zeltun-rs.exe`) and run as Administrator.

## Using `zeltun.dll`

Include [`include/zeltun.h`](include/zeltun.h) or load the exports dynamically via `LoadLibrary`:

```c
#include "zeltun.h"

// Optional pre-start settings
zeltun_configure_adapter("Zeltun-TUN", "198.18.0.2", "198.18.0.1", 1500);
zeltun_set_dns("1.1.1.1", "8.8.8.8", 1);          // NRPT enabled
zeltun_set_tun_behavior(0, 0, 120);               // block IPv6, relax fallback, 120s UDP timeout
zeltun_set_options(57, 1360);                     // QUIC block + LAN bypass + QoS + clean DNS
zeltun_add_bypass_ip("203.0.113.10");             // VPN server IP to bypass TUN

// Start TUN engine pointing to your SOCKS5 server (phys_if_index = 0 for auto-detect)
zeltun_start("127.0.0.1:10808", 0, 0x400000);

// Split mode: 0 = global, 1 = include (whitelist), 2 = exclude (blacklist)
zeltun_set_rules(ZELTUN_MODE_INCLUDE, "Discord.exe,Telegram.exe");

// Read live telemetry anytime
ZeltunStatsEx stats = {0};
zeltun_get_stats_ex(&stats);

// Clean shutdown
zeltun_stop();
```

Useful runtime hooks:
- `zeltun_update_physical_if(if_idx, gateway, lan_ip)` — switch physical adapter live on Wi-Fi/LAN change
- `zeltun_set_socks(socks_addr)` — swap upstream SOCKS5 target without restarting Wintun
- `zeltun_poll_log` / `zeltun_get_last_error` — pull engine logs and error details
- `zeltun_cleanup_stale` — clear leftover routes/NRPT rules after an unclean exit

Quick CLI test:

```bash
.\zeltun-rs.exe --socks 127.0.0.1:10808 --mode include --apps "Discord.exe"
```

---

If this project helped you, you can support it here:
https://donatr.ee/devlsam/
