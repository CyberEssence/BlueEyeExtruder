// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define BLOCK_SIZE 4096

struct request {
    __u64 phys;
    __u64 seq;
    __u32 size;
    __u32 pad;
};

struct result {
    __u64 seq;
    __s32 status;
    __u32 size;
    __u8 data[BLOCK_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct request);
} requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct result);
} results SEC(".maps");

/* Адрес переменной, а не значение direct-map base. */
const volatile __u64 page_offset_symbol = 0;
const volatile __u32 collector_tgid = 0;

SEC("tracepoint/syscalls/sys_enter_getpid")
int dump_page(void *ctx)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    if (tgid != collector_tgid)
        return 0;

    __u32 key = 0;
    struct request *req = bpf_map_lookup_elem(&requests, &key);
    struct result *res = bpf_map_lookup_elem(&results, &key);

    if (!req || !res)
        return 0;

    __u64 seq = req->seq;
    __u64 phys = req->phys;
    __u32 size = req->size;

    /* Запрос ещё не задан либо уже обработан. */
    if (!seq || res->seq == seq)
        return 0;

    res->size = 0;
    res->status = -22; /* EINVAL */

    if (!size || size > BLOCK_SIZE) {
        res->seq = seq;
        return 0;
    }

    __u64 base = 0;
    long rc = bpf_probe_read_kernel(
        &base, sizeof(base), (const void *)page_offset_symbol
    );

    if (rc) {
        res->status = (__s32)rc;
        res->seq = seq;
        return 0;
    }

    if (!base || phys > (~(__u64)0 - base)) {
        res->status = -22;
        res->seq = seq;
        return 0;
    }

    __u64 virt = base + phys;

    rc = bpf_probe_read_kernel(
        res->data, size, (const void *)virt
    );

    res->status = (__s32)rc;
    if (!rc)
        res->size = size;

    /* Маркер завершения запроса. */
    res->seq = seq;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";