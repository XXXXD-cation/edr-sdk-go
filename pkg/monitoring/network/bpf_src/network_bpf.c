// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Copyright (c) 2025 ccnochch

// Common headers for eBPF programs
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

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

// NEW: Structure to store info from kprobe to kretprobe
typedef struct {
    u64 entry_timestamp_ns; // Timestamp from kprobe entry
    u32 pid;
    u32 tgid;
    u32 uid;
    u32 gid;
    char comm[TASK_COMM_LEN];
    event_type_t original_type; // EVENT_TCP_CONNECT_V4 or _V6
    u16 dport;
    u8 daddr_v6[16];
    u8 family;
    __u64 sk_ptr_u64; // Pointer to the struct sock, stored as u64
} active_connect_info_t;

// Ring buffer for sending events to user space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB ring buffer
} events SEC(".maps");

// NEW: Hash map to track active connect calls
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240); // Max concurrent connect calls to track
    __type(key, u64);           // pid_tgid
    __type(value, active_connect_info_t);
} active_connects SEC(".maps");

// Helper function (can be reused or adapted if needed)
static __always_inline void fill_basic_proc_info(active_connect_info_t *info) {
    u64 id = bpf_get_current_pid_tgid();
    info->pid = id >> 32;
    info->tgid = id & 0xFFFFFFFF;
    u64 uid_gid = bpf_get_current_uid_gid();
    info->uid = uid_gid & 0xFFFFFFFF;
    info->gid = uid_gid >> 32;
    bpf_get_current_comm(&info->comm, sizeof(info->comm));
}

// Kprobe for tcp_v4_connect (NEW LOGIC)
SEC("kprobe/tcp_v4_connect")
int kprobe_tcp_v4_connect(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct sockaddr *uaddr = (struct sockaddr *)PT_REGS_PARM2(ctx);
    // int addr_len = (int)PT_REGS_PARM3(ctx); // addr_len is not used currently

    bpf_printk("kprobe_tcp_v4_connect: triggered\n");
    if (!sk || !uaddr) {
        bpf_printk("kprobe_tcp_v4_connect: sk or uaddr is NULL. sk: %p, uaddr: %p\n", sk, uaddr);
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    active_connect_info_t connect_info = {}; // Initialize to zero

    connect_info.entry_timestamp_ns = bpf_ktime_get_ns();
    fill_basic_proc_info(&connect_info);
    connect_info.original_type = EVENT_TCP_CONNECT_V4;
    connect_info.family = AF_INET;
    connect_info.sk_ptr_u64 = (__u64)sk; // Store the sk pointer as u64

    struct sockaddr_in *sa_in = (struct sockaddr_in *)uaddr;
    bpf_probe_read_kernel(&connect_info.dport, sizeof(connect_info.dport), &sa_in->sin_port);
    connect_info.daddr_v6[10] = 0xff;
    connect_info.daddr_v6[11] = 0xff;
    bpf_probe_read_kernel(&connect_info.daddr_v6[12], sizeof(u32), &sa_in->sin_addr.s_addr);

    if (bpf_map_update_elem(&active_connects, &pid_tgid, &connect_info, BPF_ANY) != 0) {
        bpf_printk("kprobe_tcp_v4_connect: failed to update active_connects map\n");
    }
    bpf_printk("kprobe_tcp_v4_connect: stored connect info for pid_tgid %llu\n", pid_tgid);
    return 0;
}

// Kprobe for tcp_v6_connect (NEW LOGIC)
SEC("kprobe/tcp_v6_connect")
int kprobe_tcp_v6_connect(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct sockaddr *uaddr = (struct sockaddr *)PT_REGS_PARM2(ctx);
    // int addr_len = (int)PT_REGS_PARM3(ctx); // addr_len is not used currently

    bpf_printk("kprobe_tcp_v6_connect: triggered\n");
    if (!sk || !uaddr) {
        bpf_printk("kprobe_tcp_v6_connect: sk or uaddr is NULL. sk: %p, uaddr: %p\n", sk, uaddr);
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    active_connect_info_t connect_info = {};

    connect_info.entry_timestamp_ns = bpf_ktime_get_ns();
    fill_basic_proc_info(&connect_info);
    connect_info.original_type = EVENT_TCP_CONNECT_V6;
    connect_info.family = AF_INET6;
    connect_info.sk_ptr_u64 = (__u64)sk; // Store the sk pointer as u64

    struct sockaddr_in6 *sa_in6 = (struct sockaddr_in6 *)uaddr;
    bpf_probe_read_kernel(&connect_info.dport, sizeof(connect_info.dport), &sa_in6->sin6_port);
    bpf_probe_read_kernel(&connect_info.daddr_v6, sizeof(connect_info.daddr_v6), &sa_in6->sin6_addr.in6_u.u6_addr8);

    if (bpf_map_update_elem(&active_connects, &pid_tgid, &connect_info, BPF_ANY) != 0) {
        bpf_printk("kprobe_tcp_v6_connect: failed to update active_connects map\n");
    }
    bpf_printk("kprobe_tcp_v6_connect: stored connect info for pid_tgid %llu\n", pid_tgid);
    return 0;
}

// Common Kretprobe exit logic helper
static __always_inline int handle_tcp_connect_exit(int ret_val) { // sk is no longer passed as a direct param here
    // bpf_printk("handle_tcp_connect_exit: triggered, ret_val: %d\\n", ret_val);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    active_connect_info_t *entry_ptr;

    entry_ptr = bpf_map_lookup_elem(&active_connects, &pid_tgid);
    if (!entry_ptr) {
        bpf_printk("handle_tcp_connect_exit: no active_connect_info found for pid_tgid %llu\\n", pid_tgid);
        return 0; 
    }
    // bpf_printk("handle_tcp_connect_exit: found active_connect_info for pid_tgid %llu\\n", pid_tgid);

    active_connect_info_t local_entry = *entry_ptr; // Make a copy
    bpf_map_delete_elem(&active_connects, &pid_tgid); 

    struct sock *sk = (struct sock *)local_entry.sk_ptr_u64; // Cast u64 back to sk pointer

    if (!sk) { 
        bpf_printk("handle_tcp_connect_exit: sk_ptr_u64 from map is NULL (or 0) for pid_tgid %llu\\n", pid_tgid);
        return 0;
    }
    
    network_event_data_t *event_data;
    event_data = bpf_ringbuf_reserve(&events, sizeof(*event_data), 0);
    if (!event_data) {
        bpf_printk("handle_tcp_connect_exit: failed to reserve space in ringbuf\n");
        return 0;
    }
    bpf_printk("handle_tcp_connect_exit: reserved space in ringbuf\n");

    event_data->timestamp_ns = bpf_ktime_get_ns();
    event_data->pid = local_entry.pid;
    event_data->tgid = local_entry.tgid;
    event_data->uid = local_entry.uid;
    event_data->gid = local_entry.gid;
    __builtin_memcpy(event_data->comm, local_entry.comm, sizeof(event_data->comm));
    event_data->type = local_entry.original_type; 
    event_data->family = local_entry.family;
    event_data->dport = local_entry.dport;
    __builtin_memcpy(event_data->daddr_v6, local_entry.daddr_v6, sizeof(event_data->daddr_v6));
    event_data->protocol = IPPROTO_TCP;

    if (local_entry.family == AF_INET) {
        u32 sipv4 = 0;
        BPF_CORE_READ_INTO(&sipv4, sk, __sk_common.skc_rcv_saddr);
        if (sipv4 != 0) {
            event_data->saddr_v6[10] = 0xff;
            event_data->saddr_v6[11] = 0xff;
            *((u32 *)(&event_data->saddr_v6[12])) = sipv4;
        }
         // else: saddr_v6 remains 0 if sipv4 is 0 (e.g. not yet bound)
    } else { // AF_INET6
        BPF_CORE_READ_INTO(&event_data->saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
    }

    u16 sport_h = 0;
    BPF_CORE_READ_INTO(&sport_h, sk, __sk_common.skc_num);
    event_data->sport = bpf_htons(sport_h);

    bpf_ringbuf_submit(event_data, 0);
    bpf_printk("handle_tcp_connect_exit: event submitted for pid_tgid %llu\n", pid_tgid);
    return 0;
}

// Kretprobe for tcp_v4_connect
SEC("kretprobe/tcp_v4_connect")
int kretprobe_tcp_v4_connect_exit(struct pt_regs *ctx) {
    // bpf_printk("kretprobe_tcp_v4_connect_exit: ENTRY, ctx: %p\\n", ctx);
    // bpf_printk("kretprobe_tcp_v4_connect_exit: PT_REGS_PARM1(ctx) raw value: 0x%lx\\n", PT_REGS_PARM1(ctx));
    // bpf_printk("kretprobe_tcp_v4_connect_exit: PT_REGS_RC(ctx) raw value: 0x%lx\\n", PT_REGS_RC(ctx));

    // struct sock *sk_from_regs = (struct sock *)PT_REGS_PARM1(ctx); // We know this is NULL
    int ret = (int)PT_REGS_RC(ctx);
    // bpf_printk("kretprobe_tcp_v4_connect_exit: sk_after_cast: %p, ret_value_after_cast: %d\\n", sk_from_regs, ret);

    return handle_tcp_connect_exit(ret); // Pass only ret_val
}

// Kretprobe for tcp_v6_connect
SEC("kretprobe/tcp_v6_connect")
int kretprobe_tcp_v6_connect_exit(struct pt_regs *ctx) {
    // bpf_printk("kretprobe_tcp_v6_connect_exit: ENTRY, ctx: %p\\n", ctx);
    // bpf_printk("kretprobe_tcp_v6_connect_exit: PT_REGS_PARM1(ctx) raw value: 0x%lx\\n", PT_REGS_PARM1(ctx));
    // bpf_printk("kretprobe_tcp_v6_connect_exit: PT_REGS_RC(ctx) raw value: 0x%lx\\n", PT_REGS_RC(ctx));

    // struct sock *sk_from_regs = (struct sock *)PT_REGS_PARM1(ctx); // We know this is NULL
    int ret = (int)PT_REGS_RC(ctx);
    // bpf_printk("kretprobe_tcp_v6_connect_exit: sk_after_cast: %p, ret_value_after_cast: %d\\n", sk_from_regs, ret);

    return handle_tcp_connect_exit(ret); // Pass only ret_val
}

char LICENSE[] SEC("license") = "Dual BSD/GPL"; 