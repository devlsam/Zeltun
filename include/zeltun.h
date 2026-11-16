#ifndef ZELTUN_H
#define ZELTUN_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Route actions
#define ZELTUN_ACTION_DIRECT 0
#define ZELTUN_ACTION_PROXY  1
#define ZELTUN_ACTION_DROP   2
#define BYPTUN_ACTION_DIRECT ZELTUN_ACTION_DIRECT
#define BYPTUN_ACTION_PROXY  ZELTUN_ACTION_PROXY
#define BYPTUN_ACTION_DROP   ZELTUN_ACTION_DROP

// Split modes
#define ZELTUN_MODE_GLOBAL  0
#define ZELTUN_MODE_INCLUDE 1
#define ZELTUN_MODE_EXCLUDE 2
#define BYPTUN_MODE_GLOBAL  ZELTUN_MODE_GLOBAL
#define BYPTUN_MODE_INCLUDE ZELTUN_MODE_INCLUDE
#define BYPTUN_MODE_EXCLUDE ZELTUN_MODE_EXCLUDE

// Runtime optimizer bitmask flags (default: 57 = BLOCK_QUIC | BYPASS_LAN | GAMING_QOS | CLEAN_DNS)
#define ZELTUN_OPT_BLOCK_QUIC       (1u << 0)
#define ZELTUN_OPT_MSS_CLAMP        (1u << 1)
#define ZELTUN_OPT_SNI_SNIFF        (1u << 2)
#define ZELTUN_OPT_BYPASS_LAN       (1u << 3)
#define ZELTUN_OPT_GAMING_QOS       (1u << 4)
#define ZELTUN_OPT_CLEAN_DNS        (1u << 5)
#define ZELTUN_OPT_STRICT_ANTI_LEAK (1u << 6)

// Log levels emitted to zeltun_set_log_callback / zeltun_poll_log
#define ZELTUN_LOG_INFO  0
#define ZELTUN_LOG_WARN  1
#define ZELTUN_LOG_ERROR 2

typedef struct ZeltunStatsEx {
    uint32_t struct_size;
    uint32_t is_running;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t proxy_bytes;
    uint64_t direct_bytes;
    uint64_t dropped_packets;
    uint32_t active_tcp_conns;
    uint32_t active_udp_sessions;
} ZeltunStatsEx;

typedef void (*ZeltunLogCallback)(uint8_t level, const char* message);

// Core lifecycle & routing
int32_t zeltun_start(const char* socks_addr, uint32_t phys_if_index, uint32_t ring_capacity);
int32_t zeltun_set_rules(uint8_t mode, const char* apps_csv);
int32_t zeltun_set_options(uint32_t opt_flags, uint16_t tcp_mss);
int32_t zeltun_get_stats(uint64_t* out_rx_bytes, uint64_t* out_tx_bytes, uint32_t* out_active_conns);
int32_t zeltun_stop(void);

// Extended configuration, hot-swap, and telemetry hooks
int32_t zeltun_configure_adapter(const char* adapter_name, const char* tun_ip, const char* tun_gw, uint32_t mtu);
int32_t zeltun_set_dns(const char* primary_dns, const char* secondary_dns, uint8_t enable_nrpt);
int32_t zeltun_set_tun_behavior(uint8_t ipv6_mode, uint8_t strict_anti_leak, uint32_t udp_timeout_secs);
int32_t zeltun_update_physical_if(uint32_t phys_if_index, const char* gateway, const char* lan_ip);
int32_t zeltun_set_socks(const char* socks_addr);
int32_t zeltun_add_bypass_ip(const char* ip_cstr);
int32_t zeltun_clear_bypass_ips(void);
int32_t zeltun_get_stats_ex(ZeltunStatsEx* out);
int32_t zeltun_cleanup_stale(const char* adapter_name, const char* tun_gw);
int32_t zeltun_set_log_callback(ZeltunLogCallback cb);
int32_t zeltun_poll_log(char* buf, uint32_t buf_len, uint8_t* out_level);
int32_t zeltun_get_last_error(char* buf, uint32_t buf_len);

// Backward-compatible legacy C-ABI aliases
int32_t byptun_start(const char* socks_addr, uint32_t phys_if_index, uint32_t ring_capacity);
int32_t byptun_set_rules(uint8_t mode, const char* apps_csv);
int32_t byptun_set_options(uint32_t opt_flags, uint16_t tcp_mss);
int32_t byptun_get_stats(uint64_t* out_rx_bytes, uint64_t* out_tx_bytes, uint32_t* out_active_conns);
int32_t byptun_stop(void);

#ifdef __cplusplus
}
#endif

#endif // ZELTUN_H
