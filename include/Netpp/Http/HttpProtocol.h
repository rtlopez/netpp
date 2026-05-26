#pragma once

#include <algorithm>
#include <charconv>
#include <iostream>
#include <map>
#include <memory>
#include <string>

#include "Netpp/Http/HttpException.h"
#include "Netpp/Http/HttpRequest.h"
#include "Netpp/Http/HttpResponse.h"
#include "Netpp/Protocol.h"

namespace Netpp::Http
{

class HttpProtocol : public Protocol
{
public:
  virtual ~HttpProtocol()
  {
  }

  void onConnect(ConnectionPtr conn) override
  {
    int s = conn->getId();
    _requests[s] = std::make_shared<HttpRequest>();
    std::cout << "[HTTP] " << conn->getPeerName() << " connected\n";
  }

  void onDisconnect(ConnectionPtr conn) override
  {
    int s = conn->getId();
    std::cout << "[HTTP] " << conn->getPeerName() << " disconnected\n";
    _requests.erase(s);
  }

  void onReceive(ConnectionPtr conn) override
  {
    int s = conn->getId();
    char buff[1024];
    ssize_t len = conn->recv(buff, sizeof(buff), 0);

    if (len < 0)
    {
      std::cout << "[HTTP] data error: " << len << " " << errno << "\n";
      if (errno == EAGAIN || errno == EWOULDBLOCK)
      {
        return; // it is fine
      }
      conn->setError();
      return;
    }

    if (len == 0)
    {
      conn->setClosed();
      return;
    }

    std::cout << std::string(buff, len);

    auto req = _requests[s];
    try
    {
      req->receive(buff, len);

      if (req->headerParsed() && req->bodyReceived())
      {
        const char *content =
            "<html>\n<head><title>Not Found</title></head>\n<body><h1>Not Found</h1></body>\n</html>\n";
        size_t len = std::strlen(content);
        sendHeaders(conn, req, 404, len);
        sendBody(conn, content, len);
      }
    }
    catch (const HttpException &e)
    {
      const char *content =
          "<html>\n<head><title>Invalid request</title></head>\n<body><h1>Invalid Request</h1></body>\n</html>\n";
      size_t len = std::strlen(content);
      sendHeaders(conn, req, e.code(), len);
      sendBody(conn, content, len);
      conn->setClosed();
      return;
    }
  }

private:
  void sendHeaders(ConnectionPtr conn, std::shared_ptr<HttpRequest> req, int status, size_t len)
  {
    HttpResponse res;
    res.status = status;
    res.version = req->version;
    res.headers["content-type"] = "text/html";
    res.headers["content-length"] = std::to_string(len);
    const std::string headers = res.str();
    ssize_t slen = conn->send(headers.c_str(), headers.size(), 0);
    std::cout << "[HTTP] sent headers " << slen << "\n";
  }

  void sendBody(ConnectionPtr conn, const char *content, size_t len)
  {
    ssize_t slen = conn->send(content, len, 0);
    std::cout << "[HTTP] sent body " << slen << "\n";
  }

  std::map<int, std::shared_ptr<HttpRequest>> _requests;
};

} // namespace Netpp::Http
