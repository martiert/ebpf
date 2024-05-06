#include "event.h"
#include "exec.skel.h"

#include <bpf/libbpf.h>

#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/poll.h>

#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#define MAX_EVENTS 100

static int libbpf_print_callback(enum libbpf_print_level level, const char * format, va_list args)
{
    if (level > LIBBPF_INFO)
        return 0;
    return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit()
{
    rlimit rlim = {
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
    const event * e = reinterpret_cast<event*>(data);
    printf("%-5s %-7d %-7d\n", "CLONE", e->pid, e->ppid);

    return 0;
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

int main(int argc, char ** argv)
{
    ring_buffer * rb = NULL;
    exec * skel;
    int err;
    epoll_event ev, events[MAX_EVENTS];
    int epollfd;
    int events_fd;

    libbpf_set_print(libbpf_print_callback);

    bump_memlock_rlimit();

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = exec__open();
    if (!skel) {
        fprintf(stderr, "Failed to open skel\n");
        return 1;
    }
    err = exec__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load skel\n");
        return 1;
    }
    err = exec__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach skel\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed create ringbuffer\n");
        goto cleanup;
    }

    events_fd = ring_buffer__epoll_fd(rb);

    epollfd = epoll_create1(0);
    if (epollfd == -1) {
        perror("epoll_create1");
        err = -1;
        goto cleanup;
    }
    ev.events = EPOLLIN;
    ev.data.fd = events_fd;
    err = epoll_ctl(epollfd, EPOLL_CTL_ADD, events_fd, &ev);
    if (err) {
        perror("epoll_ctl: events_fd");
        goto cleanup_epoll;
    }
    ev.events = EPOLLIN;
    ev.data.fd = STDIN_FILENO;
    err = epoll_ctl(epollfd, EPOLL_CTL_ADD, STDIN_FILENO, &ev);
    if (err) {
        perror("epoll_ctl: stdin");
        goto cleanup_epoll;
    }
    while (!exiting) {
        int nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            perror("epoll_wait");
            break;
        }
        for (int n = 0; n < nfds; ++n) {
            if (events[n].data.fd == events_fd) {
                err = ring_buffer__consume(rb);
                if (err == -EINTR) {
                    err = 0;
                    break;
                }
                if (err < 0) {
                    printf("Error polling ringbuffer: %d\n", err);
                    break;
                }
            }
            if (events[n].data.fd == STDIN_FILENO) {
                struct pollfd fds;
                char buffer[128];

                fds.fd = STDIN_FILENO;
                fds.events = POLLIN;

                while (poll(&fds, 1, 0))
                    (void) read(STDIN_FILENO, buffer, sizeof buffer);
                skel->bss->pid = atoi(buffer);
                printf("Got from stdin: %s\n", buffer);
            }
        }
    }

cleanup_epoll:
    close(epollfd);
cleanup:
    ring_buffer__free(rb);
    exec__destroy(skel);
    return err;
}
