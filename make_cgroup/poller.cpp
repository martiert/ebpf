#include "poller.hpp"

#include <fmt/format.h>

#include <sys/epoll.h>
#include <sys/resource.h>
#include <signal.h>
#include <errno.h>

#define MAX_EVENTS 100

Poller::Poller()
    : fd_(epoll_create1(0))
{
    if (fd_ == -1) {
        perror("epoll_create1");
        throw 1;
    }
}

Poller::~Poller()
{
    close(fd_);
}

void Poller::register_callback(int fd, std::function<void (int)> callback)
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

void Poller::run_once()
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
