#ifndef CGROUP_HPP
#define CGROUP_HPP

#include <filesystem>
#include <string>

class Cgroup
{
public:
    Cgroup();
    ~Cgroup();

    void create(int pid, std::string const & size);
    void remove(pid_t pid);

private:
    std::filesystem::path path_;
    bool is_v1_;
};

#endif
