#include "vmlinux.h"
#include "event.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, pid_t);
} monitored SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __uint(key_size, MAX_COMMAND);
    __uint(value_size, sizeof(__u8));
} exec_names SEC(".maps");

SEC("tp/sched/sched_process_exec")
int handle_execve(struct trace_event_raw_sched_process_exec * ctx)
{
    struct event event={0};
    unsigned fname_off;
    fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(event.command, MAX_COMMAND, (void*)ctx + fname_off);
    if (bpf_map_lookup_elem(&exec_names, &(event.command))) {
        u64 tgid;
        struct task_struct * task = (struct task_struct*) bpf_get_current_task();

        tgid = bpf_get_current_pid_tgid() >> 32;
        event.pid = tgid;
        event.ppid = BPF_CORE_READ(task, real_parent, tgid);
        event.type = Type_execve;

        bpf_map_update_elem(&monitored, &tgid, &tgid, BPF_ANY);

        bpf_ringbuf_output(&events, &event, sizeof(event), 0);
    }
    return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template * ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_delete_elem(&monitored, &pid) != 0)
        return 0;

    struct event event={0};
    struct task_struct * task = (struct task_struct*) bpf_get_current_task();
    event.pid = pid;
    event.ppid = BPF_CORE_READ(task, real_parent, pid);
    event.type = Type_exit;

    bpf_ringbuf_output(&events, &event, sizeof(event), 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
