#pragma once

#include <memory>
#include <unordered_map>

#include "Netpp/Connection.h"
#include "Netpp/EventLoop.h"
#include "Netpp/EventLoopHandler.h"
#include "Netpp/NetppDebug.h"
#include "Netpp/Protocol.h"
#include "Netpp/Socket.h"

namespace Netpp
{

class TcpServer : public EventLoopHandler
{
public:
  TcpServer(const char *addr, uint16_t port, EventLoop *loop, Protocol *protocol)
      : _addr(addr), _port(port), _loop(loop), _protocol(protocol), _s(-1)
  {
    sock_t s = Socket::create(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    debug("TcpServer::init", s);
    Socket::bind(s, _addr, _port);
    Socket::listen(s, 100);
    _s = s;
    _loop->add(s, this);
  }

  virtual ~TcpServer()
  {
    debug("TcpServer::close", _s);
    if (_s >= 0)
    {
      Socket::close(_s);
    }
  }

  virtual void handleError(sock_t s) override
  {
    try
    {
      debug("TcpServer::handleError", "close", s);
      close(s);
    }
    catch (...)
    {
      debug("TcpServer::handleError", "close", "exception", s);
    }
  }

  virtual void handle(sock_t s) override
  {
    if (s == _s)
    {
      try
      {
        debug("TcpServer::handle", "accept", s);
        sockaddr_in addr;
        sock_t as = Socket::accept(_s, addr);
        if (as <= 0)
        {
          return;
        }
        _loop->add(as, this);
        auto conn = std::make_shared<Connection>(as);
        _connections[as] = conn;
        _protocol->onConnect(conn);
        if (conn->hasError())
        {
          debug("TcpServer::handle", "accept", "error", as);
          close(as);
        }
        if (conn->isClosed())
        {
          debug("TcpServer::handle", "accept", "closed", as);
          close(as);
        }
      }
      catch (...)
      {
        debug("TcpServer::handle", "accept", "exception", s);
      }
    }
    else
    {
      try
      {
        debug("TcpServer::handle", "recv", s);
        auto it = _connections.find(s);
        if (it != _connections.end())
        {
          _protocol->onReceive(it->second);
          if (it->second->hasError())
          {
            debug("TcpServer::handle", "recv", "error", s);
            close(s);
          }
          if (it->second->isClosed())
          {
            debug("TcpServer::handle", "recv", "closed", s);
            close(s);
          }
        }
      }
      catch (...)
      {
        debug("TcpServer::handle", "recv", "exception", s);
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
    auto it = _connections.find(s);
    if (it != _connections.end())
    {
      _loop->del(s);
      _protocol->onDisconnect(it->second);
      _connections.erase(it);
    }
  }

  const char *_addr;
  uint16_t _port;
  EventLoop *_loop;
  Protocol *_protocol;
  sock_t _s;
  std::unordered_map<sock_t, ConnectionPtr> _connections;
};

} // namespace Netpp
