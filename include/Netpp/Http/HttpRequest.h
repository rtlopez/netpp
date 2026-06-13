#pragma once

#include <memory>
#include <string>

#include "Netpp/Http/HttpException.h"
#include "Netpp/Http/HttpMessage.h"
#include "Netpp/Logger/Logger.h"

namespace Netpp::Http
{
using Netpp::Logger::logger;
using Netpp::Logger::LogLevel;
static const char *HTTPR = "http";

class HttpRequest : public HttpMessage
{
public:
  std::string method;
  std::string path;

  virtual ~HttpRequest()
  {
    logger(HTTPR, LogLevel::DEBUG, "");
  }

protected:
  bool parseStartLine(const std::string &raw, size_t &pos) override
  {
    // "GET /path HTTP/1.1\r\n"
    size_t methodEnd = raw.find(' ', pos);
    if (methodEnd == std::string::npos)
    {
      return false;
    }
    method = raw.substr(pos, methodEnd - pos);

    size_t pathEnd = raw.find(' ', methodEnd + 1);
    if (pathEnd == std::string::npos)
    {
      return false;
    }
    path = raw.substr(methodEnd + 1, pathEnd - methodEnd - 1);

    size_t versionStart = pathEnd + 6; // skip " HTTP/"
    size_t versionEnd = raw.find("\r\n", versionStart);
    if (versionEnd == std::string::npos)
    {
      return false;
    }
    version = raw.substr(versionStart, versionEnd - versionStart);

    pos = versionEnd + 2;
    return true;
  }

  std::string serializeStartLine() const override
  {
    return method + " " + path + " HTTP/" + version + "\r\n";
  }

  void onParseError() override
  {
    throw HttpException(400);
  }
};

using HttpRequestPtr = std::shared_ptr<HttpRequest>;

} // namespace Netpp::Http
