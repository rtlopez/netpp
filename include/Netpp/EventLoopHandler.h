#pragma once

#include "Socket.h"

namespace Netpp
{

class EventLoopHandler
{
public:
    virtual void handle(sock_t s, uint32_t events) = 0;
};

}
