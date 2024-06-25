#include "poller.hpp"
#include "ringbuffer.hpp"
#include "cgroup.hpp"
#include "event.h"
#include "exec.skel.h"

#include <sys/resource.h>
#include <signal.h>
#include <fcntl.h>

#include <string>
#include <map>


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

    RingBuffer<event> events(std::function<int (event*)> && callback)
    {
        return RingBuffer<event>(bpf_map__fd(skel_->maps.events), std::move(callback));
    }

    exec * operator->() {
        return skel_;
    }

private:
    exec * skel_ = nullptr;
};

std::map<std::string, std::string> parse(int argc, char ** argv)
{
    std::map<std::string, std::string> result;

    for (int i = 1; i < argc; ++i) {
        std::string entry(argv[i]);
        auto colon = entry.find(':');
        result.emplace(entry.substr(0, colon), entry.substr(colon+1));
    }

    return result;
}

}

int main(int argc, char ** argv)
{
    auto cgroups = parse(argc, argv);
    Cgroup cgroup_handler;

    libbpf_set_print(libbpf_print_callback);

    bump_memlock_rlimit();

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    Skeleton skeleton;

    for (auto const & [path, _] : cgroups) {
        auto hash = hash_value(path.c_str());
        bpf_map__update_elem(skeleton->maps.exec_names, (const void*)&hash, sizeof(unsigned long), (const void*)&hash, sizeof(unsigned long), BPF_NOEXIST);
    }

    auto rb = skeleton.events([&cgroups, &cgroup_handler](event * e) {
        switch (e->type) {
            case Type_execve: {
                auto entry = cgroups.find(e->command);
                if (entry == cgroups.end()) {
                    fmt::print(stderr, "No cgroup set up for command {}\n", e->command);
                    return 0;
                }
                cgroup_handler.create(e->pid, entry->second);
                break;
            }
            case Type_exit: {
                cgroup_handler.remove(e->pid);
                break;
            }
        }
        return 0;
    });

    Poller poller;
    poller.register_callback(rb.fd(), [&rb](int) { rb.consume(); });

    while (!exiting)
        poller.run_once();
}
