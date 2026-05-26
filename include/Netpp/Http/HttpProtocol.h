#pragma once

#include <iostream>
#include <map>
#include <memory>
#include <string>

#include "Netpp/Http/HttpException.h"
#include "Netpp/Http/HttpRequest.h"
#include "Netpp/Http/HttpResponse.h"
#include "Netpp/DataEvent.h"
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

    std::cout << "[HTTP] " << s << " received(" << data.data.size() << "): " /* << std::string(data.data.begin(), data.data.end()) */ << "\n";

    auto req = _requests[s];
    try
    {
      req->receive(reinterpret_cast<const char *>(data.data.data()), data.data.size());

      if (req->headerParsed() && req->bodyReceived())
      {
        const char *content =
            "<html>\n<head><title>Not Found</title></head>\n<body><h1>Not Found</h1></body>\n</html>\n";
        size_t len = std::strlen(content);
        sendHeaders(data.conn, req, 404, len);
        sendBody(data.conn, content, len);
        data.conn->setClosed();
      }
    }
    catch (const HttpException &e)
    {
      const char *content =
          "<html>\n<head><title>Invalid request</title></head>\n<body><h1>Invalid Request</h1></body>\n</html>\n";
      size_t len = std::strlen(content);
      sendHeaders(data.conn, req, e.code(), len);
      sendBody(data.conn, content, len);
      data.conn->setClosed();
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
