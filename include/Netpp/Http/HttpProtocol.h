#pragma once

#include <functional>
#include <memory>
#include <string>

#include "Netpp/DataEvent.h"
#include "Netpp/Http/HttpException.h"
#include "Netpp/Http/HttpRequest.h"
#include "Netpp/Http/HttpResponse.h"
#include "Netpp/Logger/Logger.h"
#include "Netpp/Protocol.h"
#include "Netpp/TransportHandler.h"

namespace Netpp::Http
{
using Logger::logger;
using Logger::LogLevel;

class HttpProtocol : public Protocol
{
public:
  static constexpr const char *HTTP = "http";
  using MiddlewareCallback = std::function<void(HttpRequest &, HttpResponse &, ConnectionPtr)>;

  HttpProtocol(TransportHandler *server) : _server(server)
  {
    on(DATA, [this](ConnectionPtr conn, const DataEvent &data) { handleData(conn, data); });
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

private:
  void handleData(ConnectionPtr conn, const DataEvent &data)
  {
    auto s = conn->getId();
    logger(HTTP, LogLevel::DEBUG, s, data.buffer.size());

    HttpRequestPtr req = getRequest(conn);
    try
    {
      req->receive(reinterpret_cast<const char *>(data.buffer.data()), data.buffer.size());

      if (req->complete())
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
        DataEvent data{DataEvent::Buffer(totalSize), EventType::DISCONNECT};
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

        DataEvent body{DataEvent::Buffer(res.body.begin(), res.body.end()), EventType::DISCONNECT};
        logger(HTTP, LogLevel::DEBUG, "body", body.buffer.size());
        _server->send(conn, std::move(body));
      }
    }
  }

  TransportHandler *_server;
  MiddlewareCallback _middleware;
};

} // namespace Netpp::Http
