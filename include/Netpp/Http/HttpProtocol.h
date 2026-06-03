#pragma once

#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

#include "Netpp/DataEvent.h"
#include "Netpp/Http/HttpException.h"
#include "Netpp/Http/HttpRequest.h"
#include "Netpp/Http/HttpResponse.h"
#include "Netpp/Logger/Logger.h"
#include "Netpp/Protocol.h"
#include "Netpp/TcpServer.h"

namespace Netpp::Http
{

using Netpp::Logger::logger;
using Netpp::Logger::LogLevel;
static const char *HTTP = "http";

class HttpProtocol : public Protocol
{
public:
  using MiddlewareCallback = std::function<void(HttpRequest &, HttpResponse &, ConnectionPtr)>;

  HttpProtocol(TcpServer *server) : _server(server)
  {
  }

  virtual ~HttpProtocol()
  {
  }

  void addMiddleware(MiddlewareCallback middleware)
  {
    _middleware = std::move(middleware);
  }

  void onConnect(ConnectionPtr conn) override
  {
    int s = conn->getId();
    _requests.emplace(s, std::make_shared<HttpRequest>());
    logger(HTTP, LogLevel::DEBUG).log(s, conn->getPeerName());
  }

  void onDisconnect(ConnectionPtr conn) override
  {
    int s = conn->getId();
    logger(HTTP, LogLevel::DEBUG).log(s, conn->getPeerName());
    _requests.erase(s);
  }

  void onReceive(ConnectionPtr conn, DataEvent data) override
  {
    int s = conn->getId();

    logger(HTTP, LogLevel::DEBUG).log(s, data.buffer.size());

    auto req = _requests.at(s);
    try
    {
      req->receive(reinterpret_cast<const char *>(data.buffer.data()), data.buffer.size());

      if (req->headerParsed() && req->bodyReceived())
      {
        HttpResponse res = initResponse(*req);
        if (_middleware)
        {
          _middleware(*req, res, conn);
        }
        if (res.status == 404)
        {
          static const char content[] =
              "<html>\n<head><title>Not Found</title></head>\n<body><h1>Not Found</h1></body>\n</html>\n";
          res.setBody(content, sizeof(content) - 1);
        }
        sendResponse(conn, std::move(res));
      }
    }
    catch (const HttpException &e)
    {
      HttpResponse res = initResponse(*req);
      res.status = e.code();
      static const char content[] =
          "<html>\n<head><title>Invalid request</title></head>\n<body><h1>Invalid Request</h1></body>\n</html>\n";
      res.setBody(content, sizeof(content) - 1);
      sendResponse(conn, std::move(res));
    }
  }

private:
  HttpResponse initResponse(HttpRequest &req)
  {
    HttpResponse res;
    res.version = req.version;
    res.status = 404;
    res.headers = {{"content-type", "text/html"}};
    return res;
  }

  void sendResponse(ConnectionPtr conn, HttpResponse res)
  {
    res.headers["connection"] = std::string("close");
    if (!res.generator)
    {
      res.headers["content-length"] = std::to_string(res.body.size());
    }
    const auto headers_str = res.str();

    DataEvent hdr{DataEvent::Buffer(headers_str.begin(), headers_str.end())};
    logger(HTTP, LogLevel::DEBUG).log("headers", hdr.buffer.size());
    _server->send(conn, std::move(hdr));

    if (res.generator)
    {
      logger(HTTP, LogLevel::DEBUG).log("generator");
      _server->send(conn, std::move(res.generator));
    }
    else
    {
      DataEvent body{DataEvent::Buffer(res.body.begin(), res.body.end()), true};
      logger(HTTP, LogLevel::DEBUG).log("body", body.buffer.size());
      _server->send(conn, std::move(body));
    }
  }

  TcpServer *_server;
  std::unordered_map<int, RequestPtr> _requests;
  MiddlewareCallback _middleware;
};

} // namespace Netpp::Http
