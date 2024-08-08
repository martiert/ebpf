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

volatile bool exiting = false;

void sig_handler(int sig)
{
    exiting = true;
}

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

    while (!exiting) {
        sleep(1);
    }
}
