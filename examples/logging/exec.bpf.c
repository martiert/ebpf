#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define MAX_COMMAND 256

SEC("tp/sched/sched_process_exec")
int handle_execve(struct trace_event_raw_sched_process_exec * ctx)
{
    struct task_struct * task = (struct task_struct*) bpf_get_current_task();
    u64 tgid = bpf_get_current_pid_tgid() >> 32;
    int pid = tgid;
    int ppid = BPF_CORE_READ(task, real_parent, tgid);

    char command[MAX_COMMAND];
    unsigned fname_off;
    fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_kernel_str(command, MAX_COMMAND, (void*)ctx + fname_off);

    bpf_printk("Execing %s pid: %d ppid: %d", command, pid, ppid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
