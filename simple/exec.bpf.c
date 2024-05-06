#include "vmlinux.h"
#include "event.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter * ctx)
{
    u64 tgid;
    struct event event={0};
    struct task_struct * task = (struct task_struct*) bpf_get_current_task();

    tgid = bpf_get_current_pid_tgid() >> 32;
    event.pid = tgid;
    event.ppid = BPF_CORE_READ(task, real_parent, tgid);
    char * command = (char*) BPF_CORE_READ(ctx, args[0]);
    bpf_probe_read_str(&event.comm, sizeof(event.comm), command);

    if (event.ppid != 73478)
        return 0;
    bpf_ringbuf_output(&events, &event, sizeof(event), 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
