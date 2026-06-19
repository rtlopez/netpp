#pragma once

#include <chrono>
#include <future>
#include <memory>
#include <string>

#include "Netpp/Core/TcpHandler.h"
#include "Netpp/DataEvent.h"
#include "Netpp/Http/HttpRequest.h"
#include "Netpp/Http/HttpResponse.h"
#include "Netpp/Logger/Logger.h"
#include "Netpp/Protocol.h"

namespace Netpp::Http
{
using Logger::logger;
using Logger::LogLevel;

class HttpClientProtocol : public Protocol
{
public:
  static constexpr const char *HTTPC = "httpc";

  HttpClientProtocol(Core::TcpHandler *handler) : _handler(handler)
  {
    on(EventType::CONNECT, [this](ConnectionPtr conn, const DataEvent &) { onConnect(conn); });
    on(EventType::DATA, [this](ConnectionPtr conn, const DataEvent &data) { onData(conn, data); });
    on(EventType::DISCONNECT, [this](ConnectionPtr conn, const DataEvent &) { onDisconnect(conn); });
    on(EventType::ERROR, [this](ConnectionPtr conn, const DataEvent &) { onError(conn); });
    on(EventType::TIMEOUT, [this](ConnectionPtr conn, const DataEvent &) { onTimeout(conn); });
  }

  /// Initiates an async GET request. Returns a future that will hold the response
  /// once complete. The caller must ensure the event loop is running (e.g. loop.run()
  /// in a separate thread or after issuing all requests).
  ///
  /// Usage (pseudo-blocking with std::future):
  ///   auto future = protocol.get("example.com", 80, "/index.html");
  ///   // ... event loop is running ...
  ///   HttpResponse response = future.get(); // blocks until response arrives
  std::future<HttpResponse> get(std::string host, uint16_t port, std::string path,
                                std::chrono::milliseconds connectTimeout = std::chrono::seconds(5))
  {
    logger(HTTPC, LogLevel::DEBUG, host, port, path, connectTimeout.count());

    auto ctx = std::make_shared<RequestContext>();
    ctx->host = std::move(host);
    ctx->path = std::move(path);
    auto future = ctx->promise.get_future();

    _handler->connect(ctx->host, port, this, connectTimeout, ctx);

    return future;
  }

private:
  struct RequestContext
  {
    std::string host;
    std::string path;
    HttpResponse response;
    std::promise<HttpResponse> promise;
    bool fulfilled = false;
  };

  void onConnect(ConnectionPtr conn)
  {
    auto ctx = conn->getContext<RequestContext>();
    if (!ctx)
    {
      return;
    }

    HttpRequest req;
    req.method = "GET";
    req.path = ctx->path;
    req.version = "1.1";
    req.headers["host"] = ctx->host;
    req.headers["connection"] = "close";

    auto request = req.str();

    logger(HTTPC, LogLevel::DEBUG, conn->getId(), req.path);

    DataEvent data{.buffer = {request.begin(), request.end()}, .eventType = EventType::DATA};
    _handler->send(conn, std::move(data));
  }

  void onData(ConnectionPtr conn, const DataEvent &data)
  {
    auto ctx = conn->getContext<RequestContext>();
    if (!ctx)
    {
      return;
    }

    ctx->response.receive(reinterpret_cast<const char *>(data.buffer.data()), data.buffer.size());

    auto complete = ctx->response.headers.contains("content-length") && ctx->response.complete();

    logger(HTTPC, LogLevel::DEBUG, conn->getId(), data.buffer.size(), complete);

    if (complete)
    {
      fulfill(ctx);
    }
  }

  void onDisconnect(ConnectionPtr conn)
  {
    auto ctx = conn->getContext<RequestContext>();
    if (!ctx)
    {
      return;
    }

    logger(HTTPC, LogLevel::DEBUG, conn->getId(), ctx->response.headerParsed());

    // With Connection: close, the server closes after sending all data.
    // If headers were parsed, treat whatever we have as the complete response.
    fulfill(ctx);
  }

  void onError(ConnectionPtr conn)
  {
    auto ctx = conn->getContext<RequestContext>();
    if (!ctx || ctx->fulfilled)
    {
      return;
    }

    ctx->fulfilled = true;
    ctx->promise.set_exception(std::make_exception_ptr(std::runtime_error("connection error")));
    logger(HTTPC, LogLevel::WARN, conn->getId(), "error");
  }

  void onTimeout(ConnectionPtr conn)
  {
    auto ctx = conn->getContext<RequestContext>();
    if (!ctx || ctx->fulfilled)
    {
      return;
    }

    ctx->fulfilled = true;
    ctx->promise.set_exception(std::make_exception_ptr(std::runtime_error("connection timeout")));
    logger(HTTPC, LogLevel::WARN, conn->getId(), "timeout");
  }

  void fulfill(std::shared_ptr<RequestContext> ctx)
  {
    // Ensure promise is set only once (guard against DATA complete + DISCONNECT race)
    if (!ctx->fulfilled)
    {
      ctx->fulfilled = true;
      ctx->promise.set_value(std::move(ctx->response));
      logger(HTTPC, LogLevel::DEBUG, "");
    }
  }

  Core::TcpHandler *_handler;
};

} // namespace Netpp::Http
