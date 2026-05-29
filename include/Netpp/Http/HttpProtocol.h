#pragma once

#include <map>
#include <memory>
#include <string>

#include "Netpp/DataEvent.h"
#include "Netpp/Http/HttpException.h"
#include "Netpp/Http/HttpRequest.h"
#include "Netpp/Http/HttpResponse.h"
#include "Netpp/Protocol.h"
#include "Netpp/TcpServer.h"

namespace Netpp::Http
{

class HttpProtocol : public Protocol
{
public:
  HttpProtocol(TcpServer *server) : _server(server)
  {
  }

  virtual ~HttpProtocol()
  {
  }

  void addMiddleware(std::function<bool(HttpRequest &, HttpResponse &)> middleware)
  {
    _middleware = std::move(middleware);
  }

  void onConnect(ConnectionPtr conn) override
  {
    int s = conn->getId();
    _requests[s] = std::make_shared<HttpRequest>();
    debug("HTTP:connect", s, conn->getPeerName());
  }

  void onDisconnect(ConnectionPtr conn) override
  {
    int s = conn->getId();
    debug("HTTP:disconnect", s, conn->getPeerName());
    _requests.erase(s);
  }

  void onReceive(DataEvent data) override
  {
    int s = data.conn->getId();

    debug("HTTP:receive", s, data.buffer.size());

    auto req = _requests[s];
    try
    {
      req->receive(reinterpret_cast<const char *>(data.buffer.data()), data.buffer.size());

      if (req->headerParsed() && req->bodyReceived())
      {
        HttpResponse res;
        initResponse(*req, res);
        if (!_middleware || !_middleware(*req, res))
        {
          static const char content[] =
              "<html>\n<head><title>Not Found</title></head>\n<body><h1>Not Found</h1></body>\n</html>\n";
          res.body = std::vector<uint8_t>{content, content + sizeof(content) - 1};
        }
        sendResponse(data.conn, res);
      }
    }
    catch (const HttpException &e)
    {
      HttpResponse res;
      initResponse(*req, res);
      res.status = e.code();
      static const char content[] =
          "<html>\n<head><title>Invalid request</title></head>\n<body><h1>Invalid Request</h1></body>\n</html>\n";
      res.body = std::vector<uint8_t>{content, content + sizeof(content) - 1};
      sendResponse(data.conn, res);
    }
  }

private:
  void initResponse(HttpRequest &req, HttpResponse &res)
  {
    res.version = req.version;
    res.headers["content-type"] = "text/html";
  }

  void sendResponse(ConnectionPtr conn, HttpResponse res)
  {
    const auto bodylen = res.body.size();
    res.headers["content-length"] = std::to_string(bodylen);

    const auto headers_str = res.str();

    DataEvent hdr{conn, DataEvent::Buffer(headers_str.begin(), headers_str.end())};
    debug("HTTP:send headers", hdr.buffer.size());
    _server->send(std::move(hdr));

    DataEvent body{conn, DataEvent::Buffer(res.body.begin(), res.body.end()), true};
    debug("HTTP:send body", body.buffer.size());
    _server->send(std::move(body));
  }

  std::map<int, RequestPtr> _requests;
  TcpServer *_server;
  std::function<bool(HttpRequest &, HttpResponse &)> _middleware;
};

} // namespace Netpp::Http
