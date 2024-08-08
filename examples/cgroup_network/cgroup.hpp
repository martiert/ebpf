#ifndef CGROUP_HPP
#define CGROUP_HPP

#include <unistd.h>
#include <filesystem>
#include <string>

class Cgroup
{
public:
    class Handle
    {
    public:
        explicit Handle(int fd)
            : fd_(fd)
        {}

        ~Handle()
        {
            close(fd_);
        }

        operator int() const
        {
            return fd_;
        }

    private:
        int fd_;
    };

    Cgroup();
    ~Cgroup();

    Handle create(int pid, std::string const & size);
    void remove(pid_t pid);

private:
    std::filesystem::path path_;
    bool is_v1_;
};

#endif
