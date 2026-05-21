#pragma once

#include <string>

namespace Netpp::Http
{

class HttpException : public std::runtime_error
{
public:
  explicit HttpException(int code) : std::runtime_error("Http Error " + std::to_string(code)), _code(code)
  {
  }

  int code() const
  {
    return _code;
  }

private:
  int _code;
};

} // namespace Netpp::Http
