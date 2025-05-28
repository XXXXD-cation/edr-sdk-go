// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Copyright (c) 2025 ccnochch

// Common headers for eBPF programs
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Manually define address families if not found via vmlinux.h for bpf context
#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

#define TASK_COMM_LEN 16

// Event types
typedef enum {
    EVENT_UNKNOWN = 0,
    EVENT_TCP_CONNECT_V4 = 1,
    EVENT_TCP_CONNECT_V6 = 2,
    // EVENT_TCP_ACCEPT_V4 = 3, // Placeholder for future
    // EVENT_TCP_ACCEPT_V6 = 4, // Placeholder for future
    // EVENT_TCP_CLOSE = 5,     // Placeholder for future
} event_type_t;

// Data structure for network events sent via ring buffer
typedef struct {
    u64 timestamp_ns;
    u32 pid;
    u32 tgid;
    u32 uid;
    u32 gid;
    char comm[TASK_COMM_LEN];
    event_type_t type;
    u16 sport; // Source port (network byte order)
    u16 dport; // Destination port (network byte order)
    u8 saddr_v6[16];
    u8 daddr_v6[16];
    u8 family;   // AF_INET or AF_INET6
    u8 protocol; // IPPROTO_TCP, IPPROTO_UDP (currently only TCP)
} network_event_data_t;

// Ensure the struct is not too large for the stack or ring buffer.
// BPF_ASSERT_EVENT_SIZE is a helper macro you might define for this if needed.


// Ring buffer for sending events to user space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB ring buffer
} events SEC(".maps");


// Helper function to populate common event data
static __always_inline void fill_common_event_data(network_event_data_t *data, event_type_t type) {
    data->timestamp_ns = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    data->pid = id >> 32;
    data->tgid = id & 0xFFFFFFFF;
    u64 uid_gid = bpf_get_current_uid_gid();
    data->uid = uid_gid & 0xFFFFFFFF;
    data->gid = uid_gid >> 32;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    data->type = type;
    data->protocol = IPPROTO_TCP; // For now, all connect events are TCP
}

// Kprobe for tcp_v4_connect
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kprobe_tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len) {
    if (!sk || !uaddr) {
        return 0;
    }

    network_event_data_t *data;
    data = bpf_ringbuf_reserve(&events, sizeof(*data), 0);
    if (!data) {
        bpf_printk("network_monitor: tcp_v4_connect: failed to reserve space in ringbuf\n");
        return 0;
    }

    fill_common_event_data(data, EVENT_TCP_CONNECT_V4);
    data->family = AF_INET;

    // Destination address and port
    struct sockaddr_in *sa_in = (struct sockaddr_in *)uaddr;
    bpf_probe_read_kernel(&data->dport, sizeof(data->dport), &sa_in->sin_port);
    // Store IPv4 in IPv6-mapped format: ::ffff:ipv4_addr
    data->daddr_v6[10] = 0xff;
    data->daddr_v6[11] = 0xff;
    bpf_probe_read_kernel(&data->daddr_v6[12], sizeof(u32), &sa_in->sin_addr.s_addr);

    // Source address and port are initialized to zero as they might not be reliably available at this kprobe point.
    __builtin_memset(data->saddr_v6, 0, sizeof(data->saddr_v6));
    data->sport = 0;

    bpf_ringbuf_submit(data, 0);
    return 0;
}

// Kprobe for tcp_v6_connect
SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(kprobe_tcp_v6_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len) {
    if (!sk || !uaddr) {
        return 0;
    }
    
    network_event_data_t *data;
    data = bpf_ringbuf_reserve(&events, sizeof(*data), 0);
    if (!data) {
        bpf_printk("network_monitor: tcp_v6_connect: failed to reserve space in ringbuf\n");
        return 0;
    }

    fill_common_event_data(data, EVENT_TCP_CONNECT_V6);
    data->family = AF_INET6;

    struct sockaddr_in6 *sa_in6 = (struct sockaddr_in6 *)uaddr;
    bpf_probe_read_kernel(&data->dport, sizeof(data->dport), &sa_in6->sin6_port);
    bpf_probe_read_kernel(&data->daddr_v6, sizeof(data->daddr_v6), &sa_in6->sin6_addr.in6_u.u6_addr8);

    // Source address and port are initialized to zero.
    __builtin_memset(data->saddr_v6, 0, sizeof(data->saddr_v6));
    data->sport = 0;

    bpf_ringbuf_submit(data, 0);
    return 0;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL"; 