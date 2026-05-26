#pragma once

#include <memory>
#include <unordered_map>

#include "Netpp/Connection.h"
#include "Netpp/DataEvent.h"
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
    debug("TcpServer", s);
    Socket::bind(s, _addr, _port);
    Socket::listen(s, 100);
    _s = s;
    _loop->add(s, this);
  }

  virtual ~TcpServer()
  {
    debug("~TcpServer", _s);
    if (_s >= 0)
    {
      Socket::close(_s);
    }
  }

  virtual void handleError(sock_t s) override
  {
    try
    {
      close(s);
    }
    catch (...)
    {
      debug("TcpServer::error", "exception", s);
    }
  }

  virtual void handle(sock_t s) override
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
          debug("TcpServer::accept", "error", s, as, errno, ::strerror(errno));
          return;
        }
        _loop->add(as, this);
        auto conn = std::make_shared<Connection>(as);
        _connections[as] = conn;
        _protocol->onConnect(conn);
        
        if (conn->hasError() || conn->isClosed())
        {
          close(as);
        }
      }
      catch (...)
      {
        debug("TcpServer::accept", "exception", s);
      }
    }
    else
    {
      try
      {
        auto it = _connections.find(s);
        if (it != _connections.end())
        {
          auto& conn = it->second;

          DataEvent data{conn, std::vector<uint8_t>(4096)};
          ssize_t len = conn->recv(reinterpret_cast<char *>(data.data.data()), data.data.size(), 0);
          
          debug("TcpServer::recv", _s, s, len);

          if (len > 0)
          {
            data.data.resize(len);
            _protocol->onReceive(std::move(data));
          }
          else if (len == 0)
          {
            debug("TcpServer::disconnect", _s, s);
            conn->setClosed();
          }
          else if(errno == EAGAIN || errno == EWOULDBLOCK)
          {
            // skip
          }
          else
          {
            debug("TcpServer::recv", "error", _s, s, len, errno, ::strerror(errno));
            conn->setError();
          }

          if (conn->isClosed() || conn->hasError())
          {
            close(s);
          }
        }
        else
        {
          debug("TcpServer::recv", "unknown connection", _s, s);
          close(s);
        }
      }
      catch (...)
      {
        debug("TcpServer::recv", "exception", s);
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
