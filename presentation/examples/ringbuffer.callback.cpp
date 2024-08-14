int callback(void * ctx, void * data, size_t size)
{
    event * e = static_cast<event*>(data);
    fmt::print("{}: {} {}\n", e->command, e->pid, e->ppid);
    return 0;
}
