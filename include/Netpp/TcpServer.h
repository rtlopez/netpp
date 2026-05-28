#pragma once

#include <memory>
#include <unordered_map>

#include "Netpp/Connection.h"
#include "Netpp/DataEvent.h"
#include "Netpp/Dispatcher.h"
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
  TcpServer(const char *addr, uint16_t port, EventLoop *loop, Protocol *protocol, Dispatcher *dispatcher)
      : _addr(addr), _port(port), _loop(loop), _protocol(protocol), _dispatcher(dispatcher), _s(-1)
  {
    sock_t s = Socket::create(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    debug("TcpServer", s);
    Socket::bind(s, _addr, _port);
    Socket::listen(s, 128);
    _s = s;
    _loop->add(s, this);
  }

  virtual ~TcpServer()
  {
    debug("~TcpServer", _s);
    if (_s >= 0)
    {
      _loop->del(_s);
      Socket::close(_s);
    }
  }

  virtual void handleError(sock_t s) override
  {
    try
    {
      auto it = _connections.find(s);
      if (it != _connections.end())
      {
        _protocol->onError(it->second);
      }
      close(s);
    }
    catch (...)
    {
      debug("TcpServer::error::exception", s);
    }
  }

  virtual void handleReading(sock_t s) override
  {
    if (s == _s)
    {
      try
      {
        debug("TcpServer::accept", s);
        sockaddr_in addr;
        sock_t as = Socket::accept(_s, addr);
        if (as <= 0)
        {
          debug("TcpServer::accept::error", s, as, errno, ::strerror(errno));
          return;
        }
        auto conn = std::make_shared<Connection>(as);
        _loop->add(as, this);
        _connections.emplace(as, conn);
        _protocol->onConnect(conn);
      }
      catch (...)
      {
        debug("TcpServer::accept::exception", s);
      }
    }
    else
    {
      try
      {
        auto it = _connections.find(s);
        if (it != _connections.end())
        {
          auto &conn = it->second;

          DataEvent data{conn, DataEvent::Buffer(4096)};
          auto len = conn->recv(data.buffer.data(), data.buffer.size(), 0);

          debug("TcpServer::recv", _s, s, len);

          if (len > 0)
          {
            data.buffer.resize(static_cast<size_t>(len)); // set actual buffer size
            _dispatcher->post(std::move(data), _protocol);
          }
          else if (len == 0)
          {
            debug("TcpServer::recv::disconnect", _s, s);
            _dispatcher->send({conn, DataEvent::Buffer{}, true});
          }
          else if (errno == EAGAIN || errno == EWOULDBLOCK)
          {
            // skip
          }
          else
          {
            debug("TcpServer::recv::error", _s, s, len, errno, ::strerror(errno));
            _dispatcher->send({conn, DataEvent::Buffer{}, true});
          }
        }
        else
        {
          debug("TcpServer::recv::unknown", _s, s);
          close(s);
        }
      }
      catch (...)
      {
        debug("TcpServer::recv::exception", s);
        close(s);
      }
    }

    try
    {
      debug("TcpServer::flush");
      _dispatcher->drain([this](sock_t s) { close(s); });
    }
    catch (...)
    {
      debug("TcpServer::flush::exception");
    }
  }

  virtual void handleWriting(sock_t) override
  {
  }

private:
  void close(sock_t s)
  {
    debug("TcpServer::close", s);
    _loop->del(s);
    auto it = _connections.find(s);
    if (it != _connections.end())
    {
      _protocol->onDisconnect(it->second);
      _connections.erase(it);
    }
  }

  const char *_addr;
  uint16_t _port;
  EventLoop *_loop;
  Protocol *_protocol;
  Dispatcher *_dispatcher;
  sock_t _s;
  std::unordered_map<sock_t, ConnectionPtr> _connections;
};

} // namespace Netpp
