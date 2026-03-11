// go:build ignore
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// BPF Map to store blocked IPv4 addresses.
// Key = __be32 IP address, Value = 1 (Blocked)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, __be32);
    __type(value, __u32);
} blocked_ips SEC(".maps");

// Config map to hold dynamic settings from Go
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32); // syn_rate_limit
} ebpf_config SEC(".maps");

// Counter for dropped packets per IP
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_count SEC(".maps");

// Counter for SYN drops
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} syn_drop_count SEC(".maps");

// Token bucket state per IP for SYN rate limiting
struct token_bucket {
    __u64 last_time_ns;
    __u32 tokens;
};

// LRU Map for tracking SYN rates (avoids OOM on DDoS)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);                 // IP
    __type(value, struct token_bucket); // State
} syn_timestamps SEC(".maps");

// Helper to increment per-cpu counters safely
static __always_inline void inc_counter(void *map) {
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(map, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
}

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // Minimum check for Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // Process only IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    // 1. HARD BLOCK (Blocklist Map)
    __u32 *is_blocked = bpf_map_lookup_elem(&blocked_ips, &ip->saddr);
    if (is_blocked) {
        inc_counter(&drop_count);
        return XDP_DROP; // Extremely fast L3 drop
    }

    // 2. SYN RATE LIMITING
    if (ip->protocol == IPPROTO_TCP) {
        // TCP Header parsing
        // header length is in 32-bit words, ip->ihl
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end) {
            return XDP_PASS;
        }

        if (tcp->syn && !tcp->ack) {
            __u32 config_key = 0;
            __u32 *rate_limit = bpf_map_lookup_elem(&ebpf_config, &config_key);
            
            // If config doesn't exist or limit is 0 (disabled), allow it.
            if (!rate_limit || *rate_limit == 0) {
                return XDP_PASS;
            }
            
            __u32 limit = *rate_limit;
            struct token_bucket *tb = bpf_map_lookup_elem(&syn_timestamps, &ip->saddr);
            __u64 now = bpf_ktime_get_ns();
            
            if (!tb) {
                // First time seeing this IP: allocate initial bucket
                struct token_bucket new_tb = {
                    .last_time_ns = now,
                    .tokens = limit - 1
                };
                bpf_map_update_elem(&syn_timestamps, &ip->saddr, &new_tb, BPF_ANY);
            } else {
                // IP exists, calculate token replenish
                __u64 elapsed_ns = now - tb->last_time_ns;
                
                // Replenish rate: limit tokens per second (1,000,000,000 ns)
                __u64 added_tokens = (elapsed_ns * limit) / 1000000000ULL;
                
                if (added_tokens > 0) {
                    tb->tokens += added_tokens;
                    if (tb->tokens > limit) {
                        tb->tokens = limit;
                    }
                    tb->last_time_ns = now;
                }
                
                if (tb->tokens > 0) {
                    tb->tokens--; // Consume 1 token for this SYN
                } else {
                    // Out of tokens -> Drop SYN
                    inc_counter(&syn_drop_count);
                    return XDP_DROP;
                }
            }
        }
    }

    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";

