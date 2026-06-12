#pragma once

#include <functional>
#include <memory>
#include <string>

#include "Netpp/Core/TcpHandler.h"
#include "Netpp/DataEvent.h"
#include "Netpp/Http/HttpException.h"
#include "Netpp/Http/HttpRequest.h"
#include "Netpp/Http/HttpResponse.h"
#include "Netpp/Logger/Logger.h"
#include "Netpp/Protocol.h"

namespace Netpp::Http
{
using Logger::logger;
using Logger::LogLevel;

class HttpProtocol : public Protocol
{
public:
  static constexpr const char *HTTP = "http";
  using MiddlewareCallback = std::function<void(HttpRequest &, HttpResponse &, ConnectionPtr)>;

  HttpProtocol(Core::TcpHandler *server) : _server(server)
  {
  }

  virtual ~HttpProtocol()
  {
  }

  void addMiddleware(MiddlewareCallback middleware)
  {
    _middleware = std::move(middleware);
  }

  HttpRequestPtr getRequest(ConnectionPtr conn)
  {
    auto req = conn->getContext<HttpRequest>();
    if (!req)
    {
      req = std::make_shared<HttpRequest>();
      conn->setContext(req);
    }
    return req;
  }

  void onReceive(ConnectionPtr conn, DataEvent data) override
  {
    auto s = conn->getId();
    logger(HTTP, LogLevel::DEBUG, s, data.buffer.size());

    if (data.connect || data.disconnect)
    {
      return;
    }

    HttpRequestPtr req = getRequest(conn);
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

    if (res.generator)
    {
      DataEvent hdr{DataEvent::Buffer(headers_str.begin(), headers_str.end())};
      logger(HTTP, LogLevel::DEBUG, "headers", hdr.buffer.size());
      _server->send(conn, std::move(hdr));

      logger(HTTP, LogLevel::DEBUG, "generator");
      _server->send(conn, std::move(res.generator));
    }
    else
    {
      size_t totalSize = headers_str.size() + res.body.size();
      if (totalSize <= 4096)
      {
        DataEvent data{DataEvent::Buffer(totalSize), true};
        std::copy(headers_str.begin(), headers_str.end(), data.buffer.data());
        std::copy(res.body.begin(), res.body.end(), data.buffer.data() + headers_str.size());
        logger(HTTP, LogLevel::DEBUG, "headers+body", data.buffer.size());
        _server->send(conn, std::move(data));
      }
      else
      {
        DataEvent hdr{DataEvent::Buffer(headers_str.begin(), headers_str.end())};
        logger(HTTP, LogLevel::DEBUG, "headers", hdr.buffer.size());
        _server->send(conn, std::move(hdr));

        DataEvent body{DataEvent::Buffer(res.body.begin(), res.body.end()), true};
        logger(HTTP, LogLevel::DEBUG, "body", body.buffer.size());
        _server->send(conn, std::move(body));
      }
    }
  }

  Core::TcpHandler *_server;
  MiddlewareCallback _middleware;
};

} // namespace Netpp::Http
