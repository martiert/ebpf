#ifndef RINGBUFFER_HPP
#define RINGBUFFER_HPP

#include <bpf/libbpf.h>
#include <fmt/format.h>
#include <errno.h>

template<typename T>
class RingBuffer
{
public:
    explicit RingBuffer(int fd, std::function<int (T*)> && callback)
        : rb_(ring_buffer__new(fd, handle_event, static_cast<void*>(this), NULL))
        , callback_(std::move(callback))
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
    std::function<int (T*)> callback_;

    static int handle_event(void * ctx, void * data, size_t size)
    {
        RingBuffer<T> * ringbuffer = static_cast<RingBuffer<T>*>(ctx);
        return ringbuffer->callback_(reinterpret_cast<T*>(data));
    }
};

#endif
