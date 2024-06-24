#include "event.h"
#include "exec.skel.h"

#include <bpf/libbpf.h>

#include <fmt/format.h>

#include <sys/epoll.h>
#include <sys/resource.h>
#include <signal.h>
#include <errno.h>

#include <string>
#include <map>
#include <functional>
#include <iostream>

#define MAX_EVENTS 100

namespace
{

int libbpf_print_callback(libbpf_print_level level, const char * format, va_list args)
{
    if (level > LIBBPF_INFO)
        return 0;
    return vfprintf(stderr, format, args);
}

void bump_memlock_rlimit()
{
    rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if(setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        perror("Failed to increase RLIMIT");
        exit(1);
    }
}

int handle_event(void *, void * data, size_t)
{
    const event * e = reinterpret_cast<event*>(data);
    fmt::print("{} {} {} {}\n", "EXECVE", e->pid, e->ppid, e->command);

    return 0;
}

volatile bool exiting = false;

void sig_handler(int sig)
{
    exiting = true;
}

class Poller
{
public:
    Poller()
        : fd_(epoll_create1(0))
    {
        if (fd_ == -1) {
            perror("epoll_create1");
            throw 1;
        }
    }

    ~Poller()
    {
        close(fd_);
    }

    void register_callback(int fd, std::function<void (int)> callback)
    {
        map_.emplace(fd, callback);
        epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.fd = fd;
        if (epoll_ctl(fd_, EPOLL_CTL_ADD, fd, &ev)) {
            perror("epoll_ctl: events_fd");
            throw 1;
        }
    }

    void run_once()
    {
        epoll_event events[MAX_EVENTS];
        int nfds = epoll_wait(fd_, events, MAX_EVENTS, -1);
        if (nfds == -1 && errno != EINTR) {
            perror("epoll_wait");
            throw 1;
        }
        for (int n = 0; n < nfds; ++n) {
            int fd = events[n].data.fd;
            auto entry = map_.find(fd);
            if (entry == map_.end()) {
                fmt::print("Got an unknown file descriptor: {}\n", fd);
                throw 1;
            }
            entry->second(fd);
        }
    }

private:
    int fd_;
    std::map<int, std::function<void (int)>> map_;
};

class RingBuffer
{
public:
    explicit RingBuffer(ring_buffer * rb)
        : rb_(rb)
    {
        if (!rb_) {
            perror("creating ringbuffer");
            throw 1;
        }
    }

    ~RingBuffer()
    {
        if (rb_)
            ring_buffer__free(rb_);
    }

    int fd() const
    {
        return ring_buffer__epoll_fd(rb_);
    }

    bool consume()
    {
        int err = ring_buffer__consume(rb_);
        if (err < 0) {
            perror("consuming event from ringbuffer");
            throw 1;
        }
        return err != -EINTR;
    }

private:
    ring_buffer * rb_;
};

class Skeleton
{
public:
    Skeleton()
        : skel_(exec__open())
    {
        if (!skel_) {
            perror("Opening skeleton");
            throw 1;
        }
        int err = exec__load(skel_);
        if (err) {
            perror("Loading skeleton");
            throw 1;
        }
        err = exec__attach(skel_);
        if (err) {
            perror("Attaching skeleton");
            throw 1;
        }
    }

    ~Skeleton()
    {
        if (skel_)
            exec__destroy(skel_);
    }

    RingBuffer events(ring_buffer_sample_fn cb) const
    {
        return RingBuffer(ring_buffer__new(bpf_map__fd(skel_->maps.events), cb, NULL, NULL));
    }

    exec * operator->() {
        return skel_;
    }

private:
    exec * skel_ = nullptr;
};

}

int main(int argc, char ** argv)
{
    int err;

    libbpf_set_print(libbpf_print_callback);

    bump_memlock_rlimit();

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    Skeleton skeleton;
    RingBuffer rb = skeleton.events(handle_event);

    Poller poller;
    poller.register_callback(rb.fd(), [&rb](int) { rb.consume(); });
    poller.register_callback(STDIN_FILENO, [&skeleton](int) { 
            std::string pid;
            std::cin >> pid;
            auto hash = hash_value(pid.c_str());
            bpf_map__update_elem(skeleton->maps.exec_names, (const void*)&hash, sizeof(unsigned long), (const void*)&hash, sizeof(unsigned long), BPF_NOEXIST);
        });

    while (!exiting) {
        poller.run_once();
    }
}
