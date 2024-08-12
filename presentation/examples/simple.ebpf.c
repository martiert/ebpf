SEC("tp/sched/sched_process_exec")
int handle_execve(struct trace_event_raw_sched_process_exec * ctx)
{
    int pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct * task = bpf_get_current_task();
    int ppid = BPF_CORE_READ(task, real_parent, pid);

    char command[MAX_COMMAND];
    bpf_probe_read_kernel_str(command, MAX_COMMAND,
            ctx + (ctx->__data_loc_filename & 0xFFFF));

    bpf_printk("Execing %s pid: %d ppid: %d", command, pid, ppid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
