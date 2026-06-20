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
    on(EventType::DATA, [this](ConnectionPtr conn, const DataEvent &data) { handleData(conn, data); });
    on(EventType::DONE, [this](ConnectionPtr conn, const DataEvent &data) { handleDone(conn, data); });
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
  static bool shouldKeepAlive(const HttpRequest &req)
  {
    auto it = req.headers.find("connection");
    if (it != req.headers.end())
    {
      std::string val = it->second;
      std::transform(val.begin(), val.end(), val.begin(), ::tolower);
      if (val == "close")
      {
        return false;
      }
      if (val == "keep-alive")
      {
        return true;
      }
    }
    // HTTP/1.1 defaults to keep-alive, HTTP/1.0 defaults to close
    return req.version == "1.1";
  }

  void handleData(ConnectionPtr conn, const DataEvent &data)
  {
    auto s = conn->getId();
    logger(HTTP, LogLevel::DEBUG, s, data.buffer.size());

    auto req = getRequest(conn);
    try
    {
      req->receive(reinterpret_cast<const char *>(data.buffer.data()), data.buffer.size());

      if (req->complete())
      {
        bool keepAlive = shouldKeepAlive(*req);
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
        sendResponse(conn, std::move(res), keepAlive);
      }
    }
    catch (const HttpException &e)
    {
      HttpResponse res = initResponse(*req);
      res.status = e.code();
      static const char content[] =
          "<html>\n<head><title>Invalid request</title></head>\n<body><h1>Invalid Request</h1></body>\n</html>\n";
      res.setBody(content, sizeof(content) - 1);
      sendResponse(conn, std::move(res), false);
    }
  }

  void handleDone(ConnectionPtr conn, const DataEvent &)
  {
    auto req = getRequest(conn);
    auto close = !shouldKeepAlive(*req);
    if (close)
    {
      _server->send(conn, {.eventType = EventType::DISCONNECT});
    }
    conn->setContext(std::shared_ptr<HttpRequest>()); // Clear request context
    logger(HTTP, LogLevel::DEBUG, conn->getId(), close ? "close" : "keep-alive");
  }

  HttpResponse initResponse(HttpRequest &req)
  {
    HttpResponse res;
    res.version = req.version;
    res.status = 404;
    res.headers = {{"content-type", "text/html"}};
    return res;
  }

  void sendResponse(ConnectionPtr conn, HttpResponse res, bool keepAlive)
  {
    res.headers["connection"] = std::string{keepAlive ? "keep-alive" : "close"};
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
      auto eventType = keepAlive ? EventType::DONE : EventType::DISCONNECT;
      size_t totalSize = headers_str.size() + res.body.size();
      if (totalSize <= 4096)
      {
        DataEvent data{DataEvent::Buffer(totalSize), eventType};
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

        DataEvent body{DataEvent::Buffer(res.body.begin(), res.body.end()), eventType};
        logger(HTTP, LogLevel::DEBUG, "body", body.buffer.size());
        _server->send(conn, std::move(body));
      }
    }
  }

  TransportHandler *_server;
  MiddlewareCallback _middleware;
};

} // namespace Netpp::Http
