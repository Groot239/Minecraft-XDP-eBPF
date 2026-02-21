#ifndef HIT_COUNT
#define HIT_COUNT 10
#endif

#ifndef START_PORT
#define START_PORT 25565
#endif
#ifndef END_PORT
#define END_PORT 25565
#endif

#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"
#include "minecraft_networking.h"
#include "stats.h"

struct
{
    __uint(type,
#if IP_AND_PORT_PER_CPU
           BPF_MAP_TYPE_LRU_PERCPU_HASH
#else
           BPF_MAP_TYPE_LRU_HASH
#endif
    );
    __uint(max_entries, 4096);
    __type(key, struct ipv4_flow_key);
    __type(value, struct initial_state);
} conntrack_map SEC(".maps");

struct
{
    __uint(type,
#if IP_AND_PORT_PER_CPU
           BPF_MAP_TYPE_PERCPU_HASH
#else
           BPF_MAP_TYPE_HASH
#endif
    );
    __uint(max_entries, 65535);
    __type(key, struct ipv4_flow_key);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} player_connection_map SEC(".maps");

struct
{
    __uint(type,
#if IP_PER_CPU
           BPF_MAP_TYPE_PERCPU_HASH
#else
           BPF_MAP_TYPE_HASH
#endif
    );
    __uint(max_entries, 65535);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} connection_throttle SEC(".maps");

#if PROMETHEUS_METRICS
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct statistics);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} stats_map SEC(".maps");
#endif

static __always_inline __u8 detect_tcp_bypass(const struct tcphdr *tcp)
{
    if ((!tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst) ||
        (tcp->syn && tcp->ack) ||
        tcp->urg)
    {
        return 1;
    }
    return 0;
}

static __always_inline __s32 update_state_or_drop(const __u64 packet_size, const struct statistics *stats_ptr, const struct initial_state *initial_state, const struct ipv4_flow_key *flow_key)
{
    if (bpf_map_update_elem(&conntrack_map, flow_key, initial_state, BPF_EXIST) < 0)
    {
        count_stats(stats_ptr, DROPPED_PACKET, 1);
        count_stats(stats_ptr, DROPPED_BYTES, packet_size);
        return XDP_DROP;
    }
    count_stats(stats_ptr, STATE_SWITCH, 1);
    (void)stats_ptr;
    (void)packet_size;
    return XDP_PASS;
}

static __always_inline void remove_connection(const struct statistics *stats_ptr, const struct ipv4_flow_key *flow_key)
{
    count_stats(stats_ptr, DROP_CONNECTION, 1);
    bpf_map_delete_elem(&conntrack_map, flow_key);
    (void)stats_ptr;
}

static __always_inline __u32 switch_to_verified(const __u64 raw_packet_len, const struct statistics *stats_ptr, const struct ipv4_flow_key *flow_key)
{
    bpf_map_delete_elem(&conntrack_map, flow_key);
    __u64 now = bpf_ktime_get_ns();
    if (bpf_map_update_elem(&player_connection_map, flow_key, &now, BPF_NOEXIST) < 0)
    {
        count_stats(stats_ptr, DROPPED_BYTES, raw_packet_len);
        count_stats(stats_ptr, DROP_CONNECTION | DROPPED_PACKET, 1);
        return XDP_DROP;
    }
    count_stats(stats_ptr, VERIFIED, 1);
    (void)raw_packet_len;
    (void)stats_ptr;
    return XDP_PASS;
}

SEC("xdp")
__s32 minecraft_filter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end || ip->ihl < 5)
        return XDP_DROP;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_DROP;

    const __u16 dest_port = __builtin_bswap16(tcp->dest);

#if START_PORT == END_PORT
    if (dest_port != START_PORT)
        return XDP_PASS;
#else
    if (dest_port < START_PORT || dest_port > END_PORT)
        return XDP_PASS;
#endif

    if (tcp->doff < 5)
        return XDP_DROP;

    const __u32 tcp_hdr_len = tcp->doff * 4;
    if ((void *)tcp + tcp_hdr_len > data_end)
        return XDP_DROP;

#if PROMETHEUS_METRICS
    __u32 key = 0;
    struct statistics *stats_ptr = bpf_map_lookup_elem(&stats_map, &key);
    if (!stats_ptr)
        return XDP_DROP;
#else
    struct statistics *stats_ptr = 0;
#endif

    const __u64 raw_packet_len = (__u64)(data_end - data);
    count_stats(stats_ptr, INCOMING_BYTES, raw_packet_len);

    if (detect_tcp_bypass(tcp))
    {
        count_stats(stats_ptr, TCP_BYPASS, 1);
        goto drop;
    }

    const __u32 src_ip = ip->saddr;

    if (tcp->syn)
    {
        count_stats(stats_ptr, SYN_RECEIVE, 1);

#if CONNECTION_THROTTLE
        __u32 *hit_counter = bpf_map_lookup_elem(&connection_throttle, &src_ip);
        if (hit_counter)
        {
            if (*hit_counter > HIT_COUNT)
                goto drop;
            (*hit_counter)++;
        }
        else
        {
            __u32 new_counter = 1;
            if (bpf_map_update_elem(&connection_throttle, &src_ip, &new_counter, BPF_NOEXIST) < 0)
                goto drop;
        }
#endif
        const struct ipv4_flow_key flow_key = gen_ipv4_flow_key(src_ip, ip->daddr, tcp->source, tcp->dest);
        const struct initial_state new_state = gen_initial_state(AWAIT_ACK, 0, __builtin_bswap32(tcp->seq) + 1);
        if (bpf_map_update_elem(&conntrack_map, &flow_key, &new_state, BPF_ANY) < 0)
            goto drop;

        return XDP_PASS;
    }

    const struct ipv4_flow_key flow_key = gen_ipv4_flow_key(src_ip, ip->daddr, tcp->source, tcp->dest);
    __u64 *lastTime = bpf_map_lookup_elem(&player_connection_map, &flow_key);
    if (lastTime)
    {
        __u64 now = bpf_ktime_get_ns();
        if (*lastTime + (SECOND_TO_NANOS * 10) < now)
            *lastTime = now;
        return XDP_PASS;
    }

    struct initial_state *initial_state = bpf_map_lookup_elem(&conntrack_map, &flow_key);
    if (!initial_state)
        goto drop;

    __u32 state = initial_state->state;
    if (state == AWAIT_ACK)
    {
        if (!tcp->ack || initial_state->expected_sequence != __builtin_bswap32(tcp->seq))
            goto drop;
        initial_state->state = state = AWAIT_MC_HANDSHAKE;
        if (bpf_map_update_elem(&conntrack_map, &flow_key, initial_state, BPF_EXIST) < 0)
            goto drop;
    }

    __u8 *tcp_payload = (__u8 *)tcp + tcp_hdr_len;
    const __u16 ip_tot_len = __builtin_bswap16(ip->tot_len);
    const __u16 tcp_payload_len = ip_tot_len - (ip->ihl * 4) - tcp_hdr_len;
    __u8 *tcp_payload_end = tcp_payload + tcp_payload_len;

    if (tcp_payload_end > (__u8 *)data_end)
        goto drop;

    // ========================================================
    // ULTIMATE PPV2 EXTRACTION (NO POINTER MATH)
    // ========================================================
    __u32 real_client_ip = 0;

    if (tcp_payload + 16 <= (__u8 *)data_end && tcp_payload + 16 <= tcp_payload_end) {
        __u8 is_ppv2 = 1;
        const __u8 pp2_sig[12] = {
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
        };
        
        #pragma unroll
        for (int i = 0; i < 12; i++) {
            if (tcp_payload[i] != pp2_sig[i]) {
                is_ppv2 = 0;
                break;
            }
        }

        if (is_ppv2) {
            if (tcp_payload[13] == 0x11) { 
                // IPv4 Header detected (28 bytes)
                if (tcp_payload + 28 <= (__u8 *)data_end && tcp_payload + 28 <= tcp_payload_end) {
                    
                    __builtin_memcpy(&real_client_ip, tcp_payload + 16, sizeof(real_client_ip));
                    
                    // Flood Protection using the real IP
                    if (real_client_ip != 0) {
                        __u32 *hit_counter = bpf_map_lookup_elem(&connection_throttle, &real_client_ip);
                        if (hit_counter) {
                            if (*hit_counter > HIT_COUNT) goto drop_connection;
                            (*hit_counter)++;
                        } else {
                            __u32 new_counter = 1;
                            bpf_map_update_elem(&connection_throttle, &real_client_ip, &new_counter, BPF_NOEXIST);
                        }
                    }

                    // Handle single-packet PPv2
                    if (tcp_payload + 28 == tcp_payload_end) {
                        initial_state->expected_sequence += 28;
                        if (bpf_map_update_elem(&conntrack_map, &flow_key, initial_state, BPF_EXIST) < 0) {
                            goto drop;
                        }
                        return XDP_PASS;
                    }

                    // INSTEAD of pointer math, adjust the TCP sequence directly and drop the packet.
                    // This forces the Minecraft client to resend the handshake WITHOUT the proxy header attached.
                    initial_state->expected_sequence += 28;
                    bpf_map_update_elem(&conntrack_map, &flow_key, initial_state, BPF_EXIST);
                    return XDP_DROP;
                }
            } else if (tcp_payload[13] == 0x21) { 
                // IPv6 Header detected (52 bytes)
                if (tcp_payload + 52 <= (__u8 *)data_end && tcp_payload + 52 <= tcp_payload_end) {
                    if (tcp_payload + 52 == tcp_payload_end) {
                        initial_state->expected_sequence += 52;
                        if (bpf_map_update_elem(&conntrack_map, &flow_key, initial_state, BPF_EXIST) < 0) {
                            goto drop;
                        }
                        return XDP_PASS;
                    }
                    initial_state->expected_sequence += 52;
                    bpf_map_update_elem(&conntrack_map, &flow_key, initial_state, BPF_EXIST);
                    return XDP_DROP;
                }
            }
            goto drop;
        }
    }
    // ========================================================

    if (tcp_payload < tcp_payload_end)
    {
        if (!tcp->ack)
            goto drop_connection;

        if (initial_state->expected_sequence != __builtin_bswap32(tcp->seq))
        {
            if (++initial_state->fails > MAX_OUT_OF_ORDER)
                goto drop_connection;
            bpf_map_update_elem(&conntrack_map, &flow_key, initial_state, BPF_EXIST);
            goto drop;
        }

        if (state == AWAIT_MC_HANDSHAKE)
        {
            __s32 next_state = inspect_handshake(tcp_payload, tcp_payload_end, &initial_state->protocol, data_end, &tcp_payload);
            if (!next_state)
                goto drop;

            if (next_state == RECEIVED_LEGACY_PING)
                goto drop_connection;
            if (next_state == DIRECT_READ_STATUS_REQUEST)
                goto read_status;
            if (next_state == DIRECT_READ_LOGIN)
                goto read_login;
            
            initial_state->state = next_state;
            goto update_state_or_drop;
        }
        if (state == AWAIT_STATUS_REQUEST)
        read_status: {
            if (!inspect_status_request(tcp_payload, tcp_payload_end, data_end))
                goto drop;
            initial_state->state = AWAIT_PING;
            goto update_state_or_drop;
        }
        if (state == AWAIT_PING)
        {
            if (!inspect_ping_request(tcp_payload, tcp_payload_end, data_end))
                goto drop;
            initial_state->state = PING_COMPLETE;
            goto update_state_or_drop;
        }
        if (state == AWAIT_LOGIN)
        read_login: {
            if (!inspect_login_packet(tcp_payload, tcp_payload_end, initial_state->protocol, data_end))
                goto drop;
            goto switch_to_verified;
        }
        if (state == PING_COMPLETE)
            goto drop_connection;
    }
    return XDP_PASS;

drop_connection:
    remove_connection(stats_ptr, &flow_key);
    goto drop;
drop:
    count_stats(stats_ptr, DROPPED_PACKET, 1);
    count_stats(stats_ptr, DROPPED_BYTES, raw_packet_len);
    return XDP_DROP;
update_state_or_drop:
    initial_state->expected_sequence += tcp_payload_len;
    return update_state_or_drop(raw_packet_len, stats_ptr, initial_state, &flow_key);
switch_to_verified:
    return switch_to_verified(raw_packet_len, stats_ptr, &flow_key);
}

char _license[] SEC("license") = "Proprietary";
