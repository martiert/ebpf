#include "cgroup.hpp"

#include <fmt/format.h>

#include <fcntl.h>
#include <unistd.h>
#include <error.h>

#include <ranges>
#include <vector>
#include <fstream>
#include <string_view>
#include <thread>
#include <chrono>

namespace fs = std::filesystem;

namespace
{

const fs::path cgroup_base_path("/sys/fs/cgroup");
fs::path path;
bool is_v1;

void write_file(fs::path const & path, std::string_view data)
{
    int fd = open(path.c_str(), O_WRONLY);
    if (fd < 0)
        perror(fmt::format("Opening {}", path.string()).c_str());
    auto result = write(fd, data.data(), data.size());
    if (result == -1)
        perror(fmt::format("Write {} to {}", data, path.string()).c_str());
}

struct MountInfo
{
    std::string source;
    std::string path;
    std::string type;
    std::vector<std::string> flags;
};

void parse_cgroup_info()
{
    static bool parsed = false;
    if (parsed)
        return;

    std::vector<MountInfo> info;
    std::ifstream fs("/proc/self/mounts");
    std::string line;
    while (std::getline(fs, line)) {
        std::vector<std::string_view> parts;
        auto split = std::views::split(line, ' ');
        auto it = split.begin();
        std::string_view source(*it);
        if (source == "cgroup" || source == "cgroup2") {
            MountInfo m;
            m.source = std::string_view(*it);
            ++it;
            m.path = std::string_view(*it);
            ++it;
            m.type = std::string_view(*it);
            ++it;

            for (auto const & w : std::views::split(*it, ','))
                m.flags.emplace_back(std::string_view(w));
            info.push_back(m);
        }
    }
    MountInfo result;
    for (auto const & i : info) {
        if (i.type == "cgroup2") {
            result = i;
        } else {
            if (std::find(i.flags.begin(), i.flags.end(), "memory") != i.flags.end()) {
                result = i;
                break;
            }
        }
    }
    path = result.path;
    is_v1 = result.type == "cgroup";
    parsed = true;
}

bool is_cgroup_v1()
{
    parse_cgroup_info();
    return is_v1;
}

fs::path cgroup_path()
{
    parse_cgroup_info();
    if (!is_cgroup_v1())
        write_file(path / "cgroup.subtree_control", "+memory");

    auto cgroup = path / "ebpf_managed";
    fs::create_directory(cgroup);
    if (!is_cgroup_v1())
        write_file(cgroup / "cgroup.subtree_control", "+memory");
    return cgroup;
}

}

Cgroup::Cgroup()
    : path_(cgroup_path())
    , is_v1_(is_cgroup_v1())
{
    std::error_code ec;
    for (auto const & e : fs::directory_iterator(path_)) {
        if (fs::is_directory(e.path()))
            fs::remove(e.path(), ec);
    }
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
    if (is_cgroup_v1())
        write_file(path / "memory.limit_in_bytes", size);
    else
        write_file(path / "memory.max", size);
}

void Cgroup::remove(pid_t pid)
{
    auto pid_name = fmt::format("{}", pid);
    auto path = path_ / pid_name;
    std::error_code ec;

    int count = 0;
    fs::remove(path, ec);
    while (ec && count < 100) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        fs::remove(path, ec);
        ++count;
    }
    if (ec)
        perror(fmt::format("Failed removing cgroup", path.string()).c_str());
}
