// SPDX-License-Identifier: GPL-2.0
// ULPF kernel egress enforcement: cgroup-BPF programs attached to the ULPF
// service cgroup. connect(2) and sendmsg(2)/sendto(2) from ANY code in the
// cgroup -- Python, librdkafka, DuckDB extensions, the AWS C++ SDK, static Rust
// or C binaries -- are allowed only to destinations in the LPM allowlists.
// Everything else gets EPERM before a packet is built.
//
// Build:  clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c ulpf_egress.bpf.c -o ulpf_egress.bpf.o
// Load:   `ulpf airgap os-policy --format ebpf` renders the bpftool commands that
//         pin the programs, fill the maps and attach them to the cgroup.
//
// Return 1 = allow, 0 = deny (the kernel returns EPERM to the caller).

#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct lpm4 { __u32 prefixlen; __u32 addr; };
struct lpm6 { __u32 prefixlen; __u32 addr[4]; };

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 4096);
    __type(key, struct lpm4);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} allow4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 4096);
    __type(key, struct lpm6);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} allow6 SEC(".maps");

// counters: [0] allowed v4, [1] denied v4, [2] allowed v6, [3] denied v6
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline void count(__u32 idx) {
    __u64 *v = bpf_map_lookup_elem(&stats, &idx);
    if (v) *v += 1;
}

static __always_inline int check4(__u32 daddr_be) {
    // loopback is always allowed (local IPC, metrics scrapes)
    if ((bpf_ntohl(daddr_be) >> 24) == 127) return 1;
    struct lpm4 k = { .prefixlen = 32, .addr = daddr_be };
    if (bpf_map_lookup_elem(&allow4, &k)) { count(0); return 1; }
    count(1);
    return 0;
}

static __always_inline int check6(__u32 *a) {
    if (a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == bpf_htonl(1)) return 1;   // ::1
    struct lpm6 k = { .prefixlen = 128 };
    k.addr[0] = a[0]; k.addr[1] = a[1]; k.addr[2] = a[2]; k.addr[3] = a[3];
    if (bpf_map_lookup_elem(&allow6, &k)) { count(2); return 1; }
    count(3);
    return 0;
}

SEC("cgroup/connect4")
int ulpf_connect4(struct bpf_sock_addr *ctx) { return check4(ctx->user_ip4); }

SEC("cgroup/sendmsg4")
int ulpf_sendmsg4(struct bpf_sock_addr *ctx) { return check4(ctx->user_ip4); }

SEC("cgroup/connect6")
int ulpf_connect6(struct bpf_sock_addr *ctx) {
    __u32 a[4] = { ctx->user_ip6[0], ctx->user_ip6[1], ctx->user_ip6[2], ctx->user_ip6[3] };
    return check6(a);
}

SEC("cgroup/sendmsg6")
int ulpf_sendmsg6(struct bpf_sock_addr *ctx) {
    __u32 a[4] = { ctx->user_ip6[0], ctx->user_ip6[1], ctx->user_ip6[2], ctx->user_ip6[3] };
    return check6(a);
}

char LICENSE[] SEC("license") = "GPL";
