#pragma once

#include <charconv>
#include <string>

#include "Netpp/DataEvent.h"
#include "Netpp/Http/HttpMessage.h"
#include "Netpp/MoveOnlyFunction.h"

namespace Netpp::Http
{

class HttpResponse : public HttpMessage
{
public:
  int status = 404;
  MoveOnlyFunction<DataEvent(void)> generator;

  HttpResponse()
  {
    version = "0.9";
  }

  void setBody(std::vector<uint8_t> content)
  {
    body = std::move(content);
  }

  void setBody(const std::string &content)
  {
    body = std::vector<uint8_t>(content.begin(), content.end());
  }

  void setBody(const char *str, size_t len)
  {
    body = std::vector<uint8_t>(str, str + len);
  }

  void setGenerator(MoveOnlyFunction<DataEvent(void)> gen)
  {
    generator = std::move(gen);
  }

  static const char *codeToMessage(int code)
  {
    switch (code)
    {
    case 100:
      return "Continue";

    case 200:
      return "OK";
    case 201:
      return "Created";
    case 204:
      return "No Content";
    case 301:
      return "Moved Permanently";
    case 302:
      return "Found";
    case 304:
      return "Not Modified";

    case 400:
      return "Bad Request";
    case 401:
      return "Unauthorized";
    case 403:
      return "Forbidden";
    case 404:
      return "Not Found";
    case 405:
      return "Method Not Allowed";
    case 406:
      return "Not Acceptable";
    case 408:
      return "Request Timeout";
    case 410:
      return "Gone";
    case 411:
      return "Length Required";
    case 413:
      return "Payload Too Large";
    case 414:
      return "URI Too Long";
    case 415:
      return "Unsupported Media Type";
    case 429:
      return "Too Many Requests";

    case 500:
      return "Internal Server Error";
    case 501:
      return "Not Implemented";
    case 502:
      return "Bad Gateway";
    case 503:
      return "Service Unavailable";
    case 504:
      return "Gateway Timeout";
    }
    return "Unknown";
  }

protected:
  bool parseStartLine(const std::string &raw, size_t &pos) override
  {
    // "HTTP/1.1 200 OK\r\n"
    size_t lineEnd = raw.find("\r\n", pos);
    if (lineEnd == std::string::npos)
    {
      return false;
    }

    size_t httpSlash = raw.find('/', pos);
    if (httpSlash == std::string::npos || httpSlash >= lineEnd)
    {
      return false;
    }

    size_t versionEnd = raw.find(' ', httpSlash + 1);
    if (versionEnd == std::string::npos || versionEnd >= lineEnd)
    {
      return false;
    }
    version = raw.substr(httpSlash + 1, versionEnd - httpSlash - 1);

    size_t codeEnd = raw.find(' ', versionEnd + 1);
    if (codeEnd == std::string::npos || codeEnd >= lineEnd)
    {
      return false;
    }
    std::string_view codeStr{raw.data() + versionEnd + 1, codeEnd - versionEnd - 1};
    std::from_chars(codeStr.data(), codeStr.data() + codeStr.size(), status);

    pos = lineEnd + 2;
    return true;
  }

  std::string serializeStartLine() const override
  {
    return "HTTP/" + version + " " + std::to_string(status) + " " + codeToMessage(status) + "\r\n";
  }
};

} // namespace Netpp::Http
