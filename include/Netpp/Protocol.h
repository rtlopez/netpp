#pragma once

#include "Socket.h"

namespace Netpp
{

class Protocol
{
public:
    enum Status {
        OK,
        ERROR,
        CLOSE,
    };
    virtual Status onConnect(sock_t s) = 0;
    virtual Status onReceive(sock_t s) = 0;
    virtual Status onDisconnect(sock_t s) = 0;
};

}
