#pragma once

#include <iostream>
#include <utility>
#include <set>
#include <string>

#include "Netpp/Protocol.h"
#include "Netpp/Socket.h"

namespace Netpp
{

namespace Chat
{

class ChatProtocol: public Protocol
{
public:
    virtual ~ChatProtocol() {}

    virtual Status onConnect(sock_t s)
    {
        _clients.insert(s);

        const char buff[] = "Welcome to the chat room\n";
        ssize_t len = sizeof(buff) - 1;
        ssize_t slen = Socket::send(s, buff, len, 0);
        if(slen != len)
        {
            std::cout << "[CHAT] FIXME: not all data resent\n";
        }

        std::string ip = std::move(Socket::getpeername(s));
        std::cout << "[CHAT] " << ip << " joined room\n";

        return Protocol::OK;
    }

    virtual Status onDisconnect(sock_t s)
    {
        _clients.erase(s);

        std::string ip = std::move(Socket::getpeername(s));
        std::cout << "[CHAT] " << ip << " left room\n";

        return Protocol::OK;
    }

    virtual Status onReceive(sock_t s)
    {
        char buff[1024];
        ssize_t len = Socket::recv(s, buff, sizeof(buff), 0);

        if(len < 0)
        {
            std::cout << "[CHAT] data error: " << len << " " << errno << "\n";
            if (errno == EAGAIN || errno == EWOULDBLOCK) return Protocol::OK;
            return Protocol::ERROR;
        }

        if(len == 0)
        {
            std::cout << "[CHAT] empty data\n";
            return Protocol::CLOSE;
        }

        for(sock_t c: _clients)
        {
            if(c == s) continue;
            ssize_t slen = Socket::send(c, buff, len, 0);
            if(slen != len)
            {
                std::cout << "[CHAT] FIXME: not all data resent\n";
            }
        }

        buff[len] = '\0';
        if(buff[len - 1] == '\n') buff[len - 1] = '\0';
        if(buff[len - 2] == '\r') buff[len - 2] = '\0';

        std::cout << "[CHAT] new data: " << buff << "\n";

        return Protocol::OK;
    }
private:
    std::set<sock_t> _clients;
};

}

}