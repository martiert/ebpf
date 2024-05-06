#include "event.h"
#include "exec.skel.h"

#include <bpf/libbpf.h>

#include <sys/resource.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

static int libbpf_print_callback(enum libbpf_print_level level, const char * format, va_list args)
{
    if (level > LIBBPF_INFO)
        return 0;
    return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if(setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "Failed to increase RLIMIT: %s\n", strerror(errno));
        exit(1);
    }
}

static int handle_event(void * ctx, void * data, size_t size)
{
    const struct event * e = data;
    printf("%-5s %-7d %-7d %-16s\n", "EXECVE", e->pid, e->ppid, e->comm);

    return 0;
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

int main()
{
    struct ring_buffer * rb = NULL;
    struct exec * skel;
    int err;

    libbpf_set_print(libbpf_print_callback);

    bump_memlock_rlimit();

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = exec__open();
    exec__load(skel);
    exec__attach(skel);

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling ringbuffer: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    exec__destroy(skel);
    return err;
}
