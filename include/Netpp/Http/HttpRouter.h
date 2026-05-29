#pragma once

#include <functional>
#include <string>
#include <vector>

#include "HttpRequest.h"
#include "HttpResponse.h"

namespace Netpp::Http {

class HttpRouter {
public:
  HttpRouter() = default;
  ~HttpRouter() = default;

  void on(const std::string method, const std::string path, std::function<void(HttpRequest &, HttpResponse &)> handler)
  {
    _routes.push_back({std::move(method), std::move(path), std::move(handler)});
  }

  void handle(HttpRequest &req, HttpResponse &res)
  {
    for (const auto &route : _routes)
    {
      if (route.match(req.method, req.path))
      {
        res.status = 200;
        route.handler(req, res);
        return;
      }
    }
    res.status = 404;
  }

private:
  struct Route {
    std::string method;
    std::string path;
    std::function<void(HttpRequest &, HttpResponse &)> handler;
    bool match(const std::string& method, const std::string& path) const {
      return this->method == method && this->path == path;
    }
  };
  std::vector<Route> _routes;
};

} // namespace Netpp::Http
