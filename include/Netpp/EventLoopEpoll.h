#pragma once

#include <sys/epoll.h>
#include <map>

#include "EventLoop.h"
#include "EventLoopHandler.h"
#include "Exception.h"
#include "NetppDebug.h"
#include "Socket.h"

namespace Netpp
{

class EventLoopEpoll: public EventLoop
{
public:
    EventLoopEpoll(): _fd(-1), _running(true), _timeout(10000)
    {
        sock_t fd = ::epoll_create1(0);
        
        debug("EventLoopEpoll::init", fd);

        if (fd < 0) throw EventLoopException(errno, "epoll_create1() failed");

        _fd = fd;
    }

    virtual ~EventLoopEpoll()
    {
        debug("EventLoopEpoll::close", _fd);
        if(_fd >= 0) ::close(_fd);
    }

    virtual void add(sock_t fd, uint32_t events, EventLoopHandler* handler) override
    {
        if(!_fd) throw EventLoopException(-1, "EventLoopEpoll not initialized");

        debug("EventLoopEpoll::add", fd, events);

        epoll_event event = {events, {.fd = fd}};

        if (epoll_ctl(_fd, EPOLL_CTL_ADD, fd, &event) < 0)
        {
            throw EventLoopException(errno, "epoll_ctl(EPOLL_CTL_ADD) failed");
        }

        _handlers[fd] = handler;
    }

    virtual void del(sock_t fd) override
    {
        if(!_fd) throw EventLoopException(errno, "EventLoopEpoll not initialized");

        debug("EventLoopEpoll::del", fd);

        if (epoll_ctl(_fd, EPOLL_CTL_DEL, fd, NULL) < 0)
        {
            throw EventLoopException(errno, "epoll_ctl(EPOLL_CTL_DEL) failed");
        }

        _handlers.erase(fd);
    }

    virtual void run() override
    {
        if(!_fd) throw EventLoopException(errno, "EventLoopEpoll not initialized");

        while (_running)
        {
            int ret = ::epoll_wait(_fd, _events, MAX_EVENTS, _timeout);
            if (ret == -1)
            {
                debug("EventLoopEpoll::run", "error", ret, errno);
                if (errno == EINTR) continue; // interrupted, try again
                throw EventLoopException(errno, "epoll_wait() failed");
            }

            if (ret == 0)
            {
                // `epoll_wait` reached its timeout
                debug("EventLoopEpoll::run", "timeout", ret);
                continue;
            }

            for (int i = 0; i < ret; i++)
            {
                handle(_events[i]);
            }
        }
    }

    void handle(const epoll_event& ev)
    {
        debug("EventLoopEpoll::run", "handle", ev.data.fd, ev.events);
        EventLoopHandler* handler = _handlers[ev.data.fd];
        handler->handle(ev.data.fd, ev.events);
    }

    void stop()
    {
        _running = false;
    }

private:
    static const size_t MAX_EVENTS = 32;
    sock_t _fd;
    bool _running;
    int _timeout;
    epoll_event _events[MAX_EVENTS];
    std::map<sock_t, EventLoopHandler*> _handlers;
};

}
