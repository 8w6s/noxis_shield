#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

#ifndef bpf_htons
#define bpf_htons(x) __builtin_bswap16(x)
#endif

// This map stores the banned IPs. The key is a 32-bit IPv4 address, and the value is a 64-bit counter of dropped packets.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000); // Support up to 1 Million banned IPs
    __type(key, __u32);
    __type(value, __u64);
} blacklist SEC(".maps");

// Main XDP program
SEC("xdp_mango")
int xdp_drop_banned(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 1. Check if packet is large enough to contain Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // 2. Only process IPv4 packets (IPv6 can be added later)
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // 3. Check if packet is large enough to contain IP header
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // 4. Extract the Source IP Address
    __u32 src_ip = ip->saddr;

    // 5. Lookup the Source IP in the BPF map (Blacklist)
    __u64 *drop_count = bpf_map_lookup_elem(&blacklist, &src_ip);
    
    // 6. If IP is in the blacklist, drop the packet instantly
    if (drop_count) {
        // Increment the drop counter for analytics (optional)
        __sync_fetch_and_add(drop_count, 1);
        
        // Return XDP_DROP to discard the packet at the NIC level (Super fast!)
        return XDP_DROP;
    }

    // 7. Otherwise, pass the packet to the Linux Kernel (to NGINX/Mango WAF)
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
