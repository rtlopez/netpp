#pragma once

#include <iostream>
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

  void onConnect(ConnectionPtr conn) override
  {
    int s = conn->getId();
    _requests[s] = std::make_shared<HttpRequest>();
    std::cout << "[HTTP] " << conn->getPeerName() << " " << s << " connected\n";
  }

  void onDisconnect(ConnectionPtr conn) override
  {
    int s = conn->getId();
    std::cout << "[HTTP] " << conn->getPeerName() << " " << s << " disconnected\n";
    _requests.erase(s);
  }

  void onReceive(DataEvent data) override
  {
    int s = data.conn->getId();

    std::cout << "[HTTP] " << s << " received(" << data.buffer.size()
              << "): " /* << std::string(data.buffer.begin(), data.buffer.end()) */ << "\n";

    auto req = _requests[s];
    try
    {
      req->receive(reinterpret_cast<const char *>(data.buffer.data()), data.buffer.size());

      if (req->headerParsed() && req->bodyReceived())
      {
        const char *content =
            "<html>\n<head><title>Not Found</title></head>\n<body><h1>Not Found</h1></body>\n</html>\n";
        size_t len = std::strlen(content);
        sendHeaders(data.conn, req, 404, len);
        sendBody(data.conn, content, len);
      }
    }
    catch (const HttpException &e)
    {
      const char *content =
          "<html>\n<head><title>Invalid request</title></head>\n<body><h1>Invalid Request</h1></body>\n</html>\n";
      size_t len = std::strlen(content);
      sendHeaders(data.conn, req, e.code(), len);
      sendBody(data.conn, content, len);
    }
  }

private:
  void sendHeaders(ConnectionPtr conn, RequestPtr req, int status, size_t len)
  {
    HttpResponse res;
    res.status = status;
    res.version = req->version;
    res.headers["content-type"] = "text/html";
    res.headers["content-length"] = std::to_string(len);
    const auto headers = res.str();
    const auto slen = headers.size();
    DataEvent data{conn, DataEvent::Buffer(headers.begin(), headers.end())};
    std::cout << "[HTTP] sent headers " << slen << "\n";
    _server->send(std::move(data));
  }

  void sendBody(ConnectionPtr conn, const char *content, size_t len)
  {
    DataEvent data{conn, DataEvent::Buffer(content, content + len), true};
    std::cout << "[HTTP] sent body " << len << "\n";
    _server->send(std::move(data));
  }

  std::map<int, RequestPtr> _requests;
  TcpServer *_server;
};

} // namespace Netpp::Http
