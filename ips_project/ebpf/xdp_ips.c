// xdp_ips.c — XDP/eBPF Intrusion Prevention Module
// Attaches to NIC at XDP hook, extracts packet features,
// enforces decisions from user-space ML agent via BPF maps.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// ── Constants ────────────────────────────────────────────────────────────────
#define MAX_ENTRIES     65536
#define ACTION_PASS     0
#define ACTION_DROP     2
#define ACTION_RATELIMIT 1

// ── Data structures ──────────────────────────────────────────────────────────

// Five-tuple key to identify a flow
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  pad[3];
};

// Per-packet stats written to ring buffer for user-space
struct pkt_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  tcp_flags;
    __u16 pkt_len;
    __u64 timestamp_ns;
};

// ── BPF Maps ─────────────────────────────────────────────────────────────────

// Ring buffer: kernel → user space (packet events)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);   // 16 MB ring buffer
} pkt_ringbuf SEC(".maps");

// Enforcement map: user space → kernel (per-source-IP action)
// Key = source IP, Value = action (0=pass, 1=ratelimit, 2=drop)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key,   __u32);
    __type(value, __u32);
} enforcement_map SEC(".maps");

// Per-IP packet counter (for rate limiting)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key,   __u32);
    __type(value, __u64);
} pkt_counter SEC(".maps");

// Stats map: index 0 = total packets, 1 = dropped, 2 = rate-limited
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key,   __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

// ── Helper: increment a stats counter ────────────────────────────────────────
static __always_inline void inc_stat(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&stats_map, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

// ── XDP Main Program ─────────────────────────────────────────────────────────
SEC("xdp")
int xdp_ips_prog(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // ── Parse Ethernet header ────────────────────────────────────────────────
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only handle IPv4
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    // ── Parse IP header ──────────────────────────────────────────────────────
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip  = ip->saddr;
    __u32 dst_ip  = ip->daddr;
    __u8  proto   = ip->protocol;
    __u16 pkt_len = bpf_ntohs(ip->tot_len);

    // ── Total packet counter ─────────────────────────────────────────────────
    inc_stat(0);

    // ── Check enforcement map for this source IP ─────────────────────────────
    __u32 *action = bpf_map_lookup_elem(&enforcement_map, &src_ip);
    if (action) {
        if (*action == ACTION_DROP) {
            inc_stat(1);    // dropped counter
            return XDP_DROP;
        }
        if (*action == ACTION_RATELIMIT) {
            // Simple token bucket: allow max 100 pkts per second
            __u64 *cnt = bpf_map_lookup_elem(&pkt_counter, &src_ip);
            if (cnt) {
                __u64 now __attribute__((unused)) = bpf_ktime_get_ns();
                // If counter > 100 in this window, drop
                if (*cnt > 100) {
                    inc_stat(2);    // rate-limited counter
                    return XDP_DROP;
                }
                __sync_fetch_and_add(cnt, 1);
            }
        }
    }

    // ── Parse TCP/UDP for ports and flags ────────────────────────────────────
    __u16 src_port = 0;
    __u16 dst_port = 0;
    __u8  tcp_flags = 0;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        src_port  = bpf_ntohs(tcp->source);
        dst_port  = bpf_ntohs(tcp->dest);
        // Pack TCP flags into one byte
        tcp_flags = (tcp->fin)      |
                    (tcp->syn << 1) |
                    (tcp->rst << 2) |
                    (tcp->psh << 3) |
                    (tcp->ack << 4) |
                    (tcp->urg << 5);
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
    } else {
        // Not TCP or UDP — pass through without recording
        return XDP_PASS;
    }

    // ── Write packet event to ring buffer ────────────────────────────────────
    struct pkt_event *evt = bpf_ringbuf_reserve(
        &pkt_ringbuf, sizeof(struct pkt_event), 0);
    if (!evt)
        return XDP_PASS;    // ring buffer full — pass packet anyway

    evt->src_ip      = src_ip;
    evt->dst_ip      = dst_ip;
    evt->src_port    = src_port;
    evt->dst_port    = dst_port;
    evt->protocol    = proto;
    evt->tcp_flags   = tcp_flags;
    evt->pkt_len     = pkt_len;
    evt->timestamp_ns = bpf_ktime_get_ns();

    bpf_ringbuf_submit(evt, 0);

    return XDP_PASS;
}

// License required by BPF verifier
char LICENSE[] SEC("license") = "GPL";
