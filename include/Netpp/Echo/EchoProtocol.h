#pragma once

#include <iostream>
#include <utility>
#include <string>

#include "Netpp/Protocol.h"
#include "Netpp/Socket.h"

namespace Netpp
{

namespace Echo
{

class EchoProtocol: public Protocol
{
public:
    virtual ~EchoProtocol() {}

    virtual Status onConnect(sock_t s)
    {
        std::string ip = std::move(Socket::getpeername(s));
        std::cout << "[ECHO] conn accept: " << ip << "\n";
        return Protocol::OK;
    }

    virtual Status onDisconnect(sock_t s)
    {
        std::string ip = std::move(Socket::getpeername(s));
        std::cout << "[ECHO] conn close: " << ip << "\n";
        return Protocol::OK;
    }

    virtual Status onReceive(sock_t s)
    {
        char buff[1024];
        ssize_t len = Socket::recv(s, buff, sizeof(buff), 0);

        if(len < 0)
        {
            std::cout << "[ECHO] data error: " << len << " " << errno << "\n";
            if (errno == EAGAIN || errno == EWOULDBLOCK) return Protocol::OK;
            return Protocol::ERROR;
        }

        if(len == 0)
        {
            std::cout << "[ECHO] empty data\n";
            return Protocol::CLOSE;
        }

        ssize_t slen = Socket::send(s, buff, len, 0);

        if(slen != len)
        {
            std::cout << "[ECHO] FIXME: not all data resent\n";
        }

        buff[len] = '\0';
        if(buff[len - 1] == '\n') buff[len - 1] = '\0';
        if(buff[len - 2] == '\r') buff[len - 2] = '\0';

        std::cout << "[ECHO] new data: " << buff << "\n";

        return Protocol::OK;
    }
};

}

}
