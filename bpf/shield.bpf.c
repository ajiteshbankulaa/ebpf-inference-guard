
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Sample approximately 1 of every 64 allowed IPv4 packets.
#define SAMPLE_FACTOR 64

// Shared block policy: same layout as Day 1.
struct block_entry {
    __u64 expires_ns;
    __u32 reason;
    __u32 reserved;
};

// Per-CPU statistics: same as Day 1.
struct counters {
    __u64 pass;
    __u64 drop;
    __u64 malformed;
    __u64 ringbuf_lost;
};

// New: metadata about one sampled packet.
struct flow_event {
    __u64 ts_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u32 pkt_len;
    __u16 src_port;
    __u16 dst_port;
    __u32 ifindex;
    __u8 protocol;
    __u8 tcp_flags;
    __u16 reserved;
};
const struct flow_event *unused_flow_event __attribute__((unused));

// Ensure the event has the expected binary size.
_Static_assert(sizeof(struct flow_event) == 32,
               "flow_event must be 32 bytes");

// Map 1: source IPv4 -> block policy.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct block_entry);
} blocklist SEC(".maps");

// Map 2: per-CPU counters.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct counters);
} stats SEC(".maps");

// Map 3: 16 MiB kernel-to-userspace ring buffer.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __attribute__((always_inline)) int
allow_packet(struct counters *c)
{
    if (c)
        c->pass++;

    return XDP_PASS;
}

static __attribute__((always_inline)) int
malformed_packet(struct counters *c)
{
    if (c)
        c->malformed++;

    return allow_packet(c);
}

SEC("xdp")
int xdp_shield(struct xdp_md *ctx)
{
    // Packet memory boundaries.
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Get this CPU's statistics.
    __u32 zero = 0;
    struct counters *c =
        bpf_map_lookup_elem(&stats, &zero);

    // 1. Validate the Ethernet header.
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return malformed_packet(c);

    // 2. Only inspect IPv4.
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return allow_packet(c);

    // 3. Validate the IPv4 header.
    struct iphdr *iph = (void *)(eth + 1);

    if ((void *)(iph + 1) > data_end)
        return malformed_packet(c);

    if (iph->version != 4 || iph->ihl < 5)
        return malformed_packet(c);

    __u32 ihl_bytes = (__u32)iph->ihl * 4;

    void *l4 = (void *)iph + ihl_bytes;

    if (l4 > data_end)
        return malformed_packet(c);

    // 4. Extract the source IP.
    __u32 src_ip = iph->saddr;

    // 5. Enforce existing blocklist rules FIRST.
    struct block_entry *entry =
        bpf_map_lookup_elem(&blocklist, &src_ip);

    if (entry) {
        __u64 now = bpf_ktime_get_ns();

        if (entry->expires_ns == 0 ||
            now < entry->expires_ns) {

            if (c)
                c->drop++;

            return XDP_DROP;
        }
    }

    // 6. Sample approximately 1/64 allowed IPv4 packets.
    if ((bpf_get_prandom_u32() & (SAMPLE_FACTOR - 1)) == 0) {

        __u16 src_port = 0;
        __u16 dst_port = 0;
        __u8 tcp_flags = 0;

        // Non-initial IPv4 fragments lack an L4 header.
        if (!(bpf_ntohs(iph->frag_off) & 0x1fff)) {

            if (iph->protocol == IPPROTO_TCP) {

                struct tcphdr *tcp = l4;

                if ((void *)(tcp + 1) > data_end)
                    return malformed_packet(c);

                src_port = bpf_ntohs(tcp->source);
                dst_port = bpf_ntohs(tcp->dest);

                // TCP control flags live in byte 13.
                tcp_flags = ((__u8 *)tcp)[13];

            } else if (iph->protocol == IPPROTO_UDP) {

                struct udphdr *udp = l4;

                if ((void *)(udp + 1) > data_end)
                    return malformed_packet(c);

                src_port = bpf_ntohs(udp->source);
                dst_port = bpf_ntohs(udp->dest);
            }
        }

        // 7. Reserve one event in the ring buffer.
        struct flow_event *ev =
            bpf_ringbuf_reserve(
                &events,
                sizeof(struct flow_event),
                0
            );

        if (!ev) {
            // Do not drop the packet if telemetry fails.
            if (c)
                c->ringbuf_lost++;

        } else {
            // 8. Populate event metadata.
            ev->ts_ns = bpf_ktime_get_ns();
            ev->src_ip = src_ip;
            ev->dst_ip = iph->daddr;

            ev->pkt_len =
                (__u32)((long)data_end - (long)data);

            ev->src_port = src_port;
            ev->dst_port = dst_port;

            ev->ifindex = ctx->ingress_ifindex;
            ev->protocol = iph->protocol;
            ev->tcp_flags = tcp_flags;
            ev->reserved = 0;

            // 9. Publish the event to userspace.
            bpf_ringbuf_submit(ev, 0);
        }
    }

    // 10. The packet is allowed.
    return allow_packet(c);
}

char LICENSE[] SEC("license") = "GPL";
