#ifndef POLLER_HPP
#define POLLER_HPP

#include <map>
#include <functional>

class Poller
{
public:
    Poller();
    ~Poller();

    void register_callback(int fd, std::function<void (int)> callback);
    void run_once();

private:
    int fd_;
    std::map<int, std::function<void (int)>> map_;
};

#endif
