#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include "bridge.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct bridge_config);
} config SEC(".maps");

SEC("tc")
int conveyor_forward(struct __sk_buff *skb)
{
    __u32 key = 0;
    struct bridge_config *cfg = bpf_map_lookup_elem(&config, &key);
    if (!cfg)
        return TC_ACT_SHOT;
    __u32 target;
    if (skb->ifindex == cfg->upstream)
        target = cfg->downstream;
    else if (skb->ifindex == cfg->downstream)
        target = cfg->upstream;
    else
        return TC_ACT_SHOT;

    /* A failed or congested observer must not prevent forwarding. */
    bpf_clone_redirect(skb, cfg->mirror, 0);
    return bpf_redirect(target, 0);
}

char LICENSE[] SEC("license") = "GPL";
