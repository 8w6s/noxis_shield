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

// Counter for dropped packets per IP
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_count SEC(".maps");

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

    // Check if the source IP matches the blocked IPs map
    __u32 *is_blocked = bpf_map_lookup_elem(&blocked_ips, &ip->saddr);
    if (is_blocked) {
        // Increment global drop counter map
        __u32 key = 0;
        __u64 *count = bpf_map_lookup_elem(&drop_count, &key);
        if (count) {
            __sync_fetch_and_add(count, 1);
        }

        // Extremely fast L3 drop in kernel!
        return XDP_DROP;
    }

    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
