SEC("tp/sched/sched_process_exit")
int handle_exit(void *)
{
  pid_t tgid = bpf_get_current_pid_tgid();
  pid_t pid = tgid >> 32;
  if (tgid != pid && 
    bpf_map_delete_elem(&monitored, &pid)
        != 0)
      return 0;

  struct event event={0};
  event.pid = pid;
  event.type = Type_exit;
  bpf_ringbuf_output(&events, &event,
          sizeof event, 0);
  return 0;
}
