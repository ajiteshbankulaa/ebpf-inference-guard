
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct block_entry {
    __u64 expires_ns;
    __u32 reason;
    __u32 reserved;
};

struct counters {
    __u64 pass;
    __u64 drop;
    __u64 malformed;
    __u64 ringbuf_lost;
};

struct packet_event {
    __u64 timestamp_ns;
    __u32 src_ip;
    __u32 action;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct block_entry);
} blocklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct counters);
} stats SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

static __attribute__((always_inline)) inline int
allow_packet(struct counters *c)
{
    if (c)
        c->pass++;

    return XDP_PASS;
}

static __attribute__((always_inline)) inline int
malformed_packet(struct counters *c)
{
    if (c)
        c->malformed++;

    return allow_packet(c);
}

SEC("xdp")
int xdp_shield(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u32 zero = 0;
    struct counters *c =
        bpf_map_lookup_elem(&stats, &zero);

    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return malformed_packet(c);

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return allow_packet(c);

    struct iphdr *iph = (void *)(eth + 1);

    if ((void *)(iph + 1) > data_end)
        return malformed_packet(c);

    if (iph->version != 4 || iph->ihl < 5)
        return malformed_packet(c);

    __u32 ihl_bytes = (__u32)iph->ihl * 4;

    if ((void *)iph + ihl_bytes > data_end)
        return malformed_packet(c);

    __u32 src_ip = iph->saddr;

    struct block_entry *entry = bpf_map_lookup_elem(&blocklist, &src_ip);

    if (entry) {
        __u64 now = bpf_ktime_get_ns();

        if (entry->expires_ns == 0 ||
            now < entry->expires_ns) {

  
            if (c)
                c->drop++;

            if (c && ((c->drop - 1) & 7) == 0) {
                struct packet_event *event =
                    bpf_ringbuf_reserve(
                        &events,
                        sizeof(struct packet_event),
                        0
                    );

                if (event) {
                    event->timestamp_ns = now;
                    event->src_ip = src_ip;
                    event->action = XDP_DROP;

                    bpf_ringbuf_submit(event, 0);
                } else {
                    c->ringbuf_lost++;
                }
            }

            return XDP_DROP;
        }
    }

    return allow_packet(c);
}

char LICENSE[] SEC("license") = "GPL";
