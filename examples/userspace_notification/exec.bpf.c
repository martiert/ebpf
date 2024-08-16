#include "vmlinux.h"
#include "event.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define MAX_COMMAND 256

SEC(".bss")
int parent_pid = 0;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tp/sched/sched_process_exec")
int handle_execve(struct trace_event_raw_sched_process_exec * ctx)
{
    struct task_struct * task = (struct task_struct*) bpf_get_current_task();
    u64 tgid = bpf_get_current_pid_tgid() >> 32;
    int pid = tgid;
    int ppid = BPF_CORE_READ(task, real_parent, tgid);
    if (ppid != parent_pid)
        return 0;

    char command[MAX_COMMAND];
    unsigned fname_off;
    fname_off = ctx->__data_loc_filename & 0xFFFF;

    struct event e;
    e.pid = pid;
    e.ppid = ppid;
    bpf_probe_read_kernel_str(e.command, MAX_COMMAND, (void*)ctx + fname_off);
    bpf_ringbuf_output(&events, &e, sizeof e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
