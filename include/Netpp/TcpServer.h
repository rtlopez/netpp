#pragma once

#include "Netpp/Socket.h"
#include "Netpp/EventLoop.h"
#include "Netpp/EventLoopHandler.h"
#include "Netpp/Protocol.h"
#include "Netpp/NetppDebug.h"

namespace Netpp
{

class TcpServer: public EventLoopHandler
{
public:
    TcpServer(const char * addr, uint16_t port, EventLoop* loop, Protocol* protocol):
        _addr(addr), _port(port), _loop(loop), _protocol(protocol), _s(-1)
    {
        debug("TcpServer::init", s);
        sock_t s = Socket::create(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
        Socket::bind(s, _addr, _port);
        Socket::listen(s, 100);
        _s = s;
        _loop->add(s, EPOLLIN | EPOLLPRI, this);
    }
    virtual ~TcpServer()
    {
        debug("TcpServer::close", _s);
        if(_s >= 0) ::close(_s);
    }

    virtual void handle(sock_t s, uint32_t events) override
    {
        if (s == _s)
        {
            try {
                debug("TcpServer::handle", "accept", s, events);
                sockaddr_in addr;
                sock_t as = Socket::accept(_s, addr);
                if(as <= 0) return;
                _loop->add(as, EPOLLIN | EPOLLPRI, this);
                Protocol::Status status = _protocol->onConnect(as);
                if(status == Protocol::CLOSE || status == Protocol::ERROR)
                {
                    close(as);
                }
            } catch(...) {
                debug("TcpServer::handle", "accept", "exception", s, events);
            }
        }
        else if (events & (EPOLLERR | EPOLLHUP))
        {
            try {
                debug("TcpServer::handle", "close", s, events);
                close(s);
            } catch(...) {
                debug("TcpServer::handle", "close", "exception", s, events);
            }
        }
        else
        {
            try {
                debug("TcpServer::handle", "recv", s, events);
                Protocol::Status status = _protocol->onReceive(s);
                if(status == Protocol::CLOSE || status == Protocol::ERROR)
                {
                    close(s);
                }
            } catch(...) {
                debug("TcpServer::handle", "recv", "exception", s, events);
                close(s);
            }
        }
    }

    sock_t native() const
    {
        return _s;
    }
private:
    void close(sock_t s)
    {
        debug("TcpServer::close", s);
        _loop->del(s);
        _protocol->onDisconnect(s);
        ::close(s);
    }

    const char * _addr;
    uint16_t _port;
    EventLoop* _loop;
    Protocol* _protocol;
    sock_t _s;
};

}
