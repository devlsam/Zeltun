use std::ffi::CString;
use std::io::{self, BufRead, Write};
use zeltun::ffi::{zeltun_get_stats, zeltun_set_options, zeltun_set_rules, zeltun_start, zeltun_stop};
use zeltun::relay::get_working_set_mb;

fn print_banner() {
    println!("\n  ███████╗███████╗██╗  ████████╗██╗   ██╗███╗   ██╗\n  ╚══███╔╝██╔════╝██║  ╚══██╔══╝██║   ██║████╗  ██║\n    ███╔╝ █████╗  ██║     ██║   ██║   ██║██╔██╗ ██║\n   ███╔╝  ██╔══╝  ██║     ██║   ██║   ██║██║╚██╗██║\n  ███████╗███████╗███████╗██║   ╚██████╔╝██║ ╚████║\n  ╚══════╝╚══════╝╚══════╝╚═╝    ╚═════╝ ╚═╝  ╚═══╝\n  ZELTUN (RUST ENGINE v2.5.0) • ULTRA-LOW LATENCY CORE\n");
}

fn parse_mode_str(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "include" | "whitelist" | "1" => 1,
        "exclude" | "blacklist" | "2" => 2,
        _ => 0,
    }
}

fn mode_name(mode: u8) -> &'static str {
    match mode {
        1 => "Include (Per-App Proxy)",
        2 => "Exclude (Bypass Selected)",
        _ => "Global (All Proxied)",
    }
}

fn main() {
    print_banner();

    let args: Vec<String> = std::env::args().collect();
    let mut socks_addr = "127.0.0.1:10808".to_string();
    let mut if_index = 0u32;
    let mut mode = 0u8;
    let mut apps_csv = String::new();
    let mut opt_flags = zeltun::config::DEFAULT_OPTS;
    let mut tcp_mss = zeltun::config::DEFAULT_TCP_MSS;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--socks" => if i + 1 < args.len() { socks_addr = args[i + 1].clone(); i += 1; },
            "--iface" => if i + 1 < args.len() { if_index = args[i + 1].parse().unwrap_or(0); i += 1; },
            "--mode" => if i + 1 < args.len() { mode = parse_mode_str(&args[i + 1]); i += 1; },
            "--apps" => if i + 1 < args.len() { apps_csv = args[i + 1].clone(); i += 1; },
            "--opts" => if i + 1 < args.len() { opt_flags = args[i + 1].parse().unwrap_or(zeltun::config::DEFAULT_OPTS); i += 1; },
            "--mss" => if i + 1 < args.len() { tcp_mss = args[i + 1].parse().unwrap_or(zeltun::config::DEFAULT_TCP_MSS); i += 1; },
            "--help" | "-h" => {
                println!("Usage: zeltun-rs [OPTIONS]\nOptions:\n  --socks <ADDR>     SOCKS5 upstream address [default: 127.0.0.1:10808]\n  --iface <INDEX>    Physical network adapter index [default: 0]\n  --mode <MODE>      Split tunnel mode: global | include | exclude [default: global]\n  --apps <APPS_CSV>  Target apps csv (e.g. 'chrome.exe,discord.exe')\n  --opts <FLAGS>     Runtime optimizer flags [default: 57]\n  --mss <BYTES>      TCP MSS clamp ceiling [default: 1360]");
                return;
            }
            _ => {}
        }
        i += 1;
    }

    let mut if_name = String::new();
    if if_index == 0 {
        let phy = zeltun::driver::detect_physical_adapter();
        if_index = phy.if_index;
        if_name = phy.adapter_name;
    } else if let Some((alias, _)) = zeltun::driver::adapter::get_adapter_details(if_index) {
        if_name = alias;
    }

    zeltun_set_options(opt_flags, tcp_mss);

    println!("[INIT] SOCKS5 Upstream : {}", socks_addr);
    if !if_name.is_empty() {
        println!("[INIT] Physical Adapter: {} (Index: {})", if_name, if_index);
    } else {
        println!("[INIT] Physical IfIndex: {}", if_index);
    }
    println!("[INIT] Split Mode      : {}", mode_name(mode));
    if !apps_csv.is_empty() {
        println!("[INIT] Target Apps     : {}", apps_csv);
    }
    println!("[INIT] Tun Optimizers  : Flags=0x{:02X} ({}), MSS={}", opt_flags, opt_flags, tcp_mss);

    let c_socks = CString::new(socks_addr).unwrap();
    let ret = zeltun_start(c_socks.as_ptr(), if_index, 0x400000);
    if ret != 0 {
        eprintln!("[ERROR] Failed to start Zeltun engine: {}", ret);
        return;
    }

    if !apps_csv.is_empty() || mode != 0 {
        let c_apps = CString::new(apps_csv.as_str()).unwrap();
        zeltun_set_rules(mode, c_apps.as_ptr());
    }

    println!("\nEngine started successfully.\nType 'stats' to view metrics.\nType 'opts <flags> [mss]' to live-tune optimizers.\nType 'mode <global|include|exclude> [apps_csv]' to alter routing.\nType 'stop' or 'exit' to shut down.\n");

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        match parts[0].to_lowercase().as_str() {
            "stats" => {
                let (mut rx, mut tx, mut conns) = (0u64, 0u64, 0u32);
                zeltun_get_stats(&mut rx, &mut tx, &mut conns);
                let ram = get_working_set_mb();
                println!("--------------------------------------------------");
                println!("  Working Set RAM : {:.2} MB", ram);
                println!("  RX Transferred  : {:.2} MB ({} bytes)", rx as f64 / (1024.0 * 1024.0), rx);
                println!("  TX Transferred  : {:.2} MB ({} bytes)", tx as f64 / (1024.0 * 1024.0), tx);
                println!("  Active Conns    : {}", conns);
                println!("--------------------------------------------------");
            }
            "opts" => {
                if parts.len() < 2 {
                    println!("Usage: opts <flags> [mss]");
                    continue;
                }
                let flags: u32 = parts[1].parse().unwrap_or(zeltun::config::DEFAULT_OPTS);
                let mss: u16 = if parts.len() >= 3 { parts[2].parse().unwrap_or(zeltun::config::DEFAULT_TCP_MSS) } else { zeltun::config::DEFAULT_TCP_MSS };
                zeltun_set_options(flags, mss);
                println!("[UPDATED] Options Flags: 0x{:02X} ({}), MSS: {}", flags, flags, mss);
            }
            "mode" => {
                if parts.len() < 2 {
                    println!("Usage: mode <global|include|exclude> [apps_csv]");
                    continue;
                }
                let new_mode = parse_mode_str(parts[1]);
                let new_apps = if parts.len() >= 3 { parts[2..].join(" ") } else { String::new() };
                let c_apps = CString::new(new_apps.as_str()).unwrap();
                zeltun_set_rules(new_mode, c_apps.as_ptr());
                println!("[UPDATED] Routing Mode set to: {}", mode_name(new_mode));
                if !new_apps.is_empty() { println!("[UPDATED] Target Apps: {}", new_apps); }
            }
            "stop" | "exit" | "quit" => {
                println!("Stopping Zeltun engine...");
                zeltun_stop();
                println!("Engine stopped cleanly. Goodbye.");
                break;
            }
            "help" => {
                println!("Available commands:\n  stats                                          - View real-time RAM & metrics\n  opts <flags> [mss]                             - Hot-tune engine optimizer flags\n  mode <global|include|exclude> [app1.exe,...]   - Hot-reload split tunneling rules\n  stop                                           - Stop engine and exit");
            }
            other => println!("Unknown command: '{}'. Type 'help' for available commands.", other),
        }

        print!("zeltun> ");
        let _ = stdout.flush();
    }
}
