#pragma once

#include "Socket.h"
#include "EventLoopHandler.h"

namespace Netpp
{

class EventLoop
{
public:
    virtual void add(sock_t fd, uint32_t events, EventLoopHandler* handler) = 0;
    virtual void del(sock_t fd) = 0;
    virtual void run() = 0;
};

}
