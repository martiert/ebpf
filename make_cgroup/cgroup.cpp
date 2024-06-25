#include "cgroup.hpp"

#include <fmt/format.h>

#include <fcntl.h>
#include <unistd.h>
#include <error.h>

#include <string_view>

namespace fs = std::filesystem;

namespace
{

const fs::path cgroup_base_path("/sys/fs/cgroup");

void write_file(fs::path const & path, std::string_view data)
{
    int fd = open(path.c_str(), O_WRONLY);
    if (fd < 0)
        perror(fmt::format("Opening {}", path.string()).c_str());
    auto result = write(fd, data.data(), data.size());
    if (result == -1)
        perror(fmt::format("Write {} to {}", data, path.string()).c_str());
}

bool is_cgroup_v1()
{
    static bool searched = false;
    static bool is_v1;
    if (searched)
        return is_v1;

    is_v1 = !fs::exists(cgroup_base_path / "cgroup.procs");
    return is_v1;
}

fs::path cgroup_path()
{
    fs::path cgroup = cgroup_base_path;
    if (is_cgroup_v1()) {
        cgroup /= "memory/ebpf_managed";
        fs::create_directory(cgroup);
        return cgroup;
    }

    write_file(cgroup / "cgroup.subtree_control", "+memory");
    cgroup = cgroup / "ebpf_managed";
    fs::create_directory(cgroup);
    write_file(cgroup / "cgroup.subtree_control", "+memory");
    return cgroup;
}

}

Cgroup::Cgroup()
    : path_(cgroup_path())
    , is_v1_(is_cgroup_v1())
{
}

Cgroup::~Cgroup()
{
    std::error_code ec;
    fs::remove(path_, ec);
}

void Cgroup::create(int pid, std::string const & size)
{
    auto pid_name = fmt::format("{}", pid);
    auto path = path_ / pid_name;
    fs::create_directory(path);

    write_file(path / "cgroup.procs", pid_name);
    write_file(path / "memory.max", size);
}
