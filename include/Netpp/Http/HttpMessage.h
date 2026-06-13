#pragma once

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace Netpp::Http
{

class HttpMessage
{
public:
  std::string version;
  std::map<std::string, std::string> headers;
  std::vector<uint8_t> body;

  virtual ~HttpMessage() = default;

  void receive(const char *c, size_t len)
  {
    if (!len)
    {
      return;
    }

    if (!_headerReceived)
    {
      std::string s{c, len};
      size_t pos = s.find("\r\n\r\n");
      if (_raw.empty())
      {
        _raw.reserve(std::max<size_t>(1024, len));
      }
      if (pos == std::string::npos)
      {
        std::copy(c, c + len, std::back_inserter(_raw));
      }
      else
      {
        std::copy(c, c + pos + 4, std::back_inserter(_raw));
        _headerReceived = true;
        _headerParsed = parse();
        if (!_headerParsed)
        {
          onParseError();
        }
        if (pos + 4 < len)
        {
          std::copy(c + pos + 4, c + len, std::back_inserter(body));
        }
      }
    }
    else
    {
      std::copy(c, c + len, std::back_inserter(body));
    }
  }

  bool headerReceived() const
  {
    return _headerReceived;
  }

  bool headerParsed() const
  {
    return _headerParsed;
  }

  bool bodyReceived() const
  {
    return _headerParsed && body.size() >= _expectedBodySize;
  }

  bool complete() const
  {
    return headerParsed() && bodyReceived();
  }

  std::string str() const
  {
    std::ostringstream ss;
    ss << serializeStartLine();
    for (const auto &[key, val] : headers)
    {
      ss << key << ": " << val << "\r\n";
    }
    ss << "\r\n";
    return std::move(ss).str();
  }

protected:
  virtual bool parseStartLine(const std::string &raw, size_t &pos) = 0;
  virtual std::string serializeStartLine() const = 0;
  virtual void onParseError()
  {
  }

private:
  bool parse()
  {
    std::string s{_raw.begin(), _raw.end()};
    size_t from = 0;

    if (!parseStartLine(s, from))
    {
      return false;
    }
    return parseHeaders(s, from);
  }

  bool parseHeaders(const std::string &s, size_t from)
  {
    while (true)
    {
      size_t to = s.find("\r\n", from);
      if (to == std::string::npos)
      {
        return false;
      }
      if (from == to)
      {
        return true;
      }

      std::string line = s.substr(from, to - from);
      size_t cto = line.find(':');
      if (cto == std::string::npos)
      {
        return false;
      }

      std::string key = trim(line.substr(0, cto));
      std::string val = trim(line.substr(cto + 1));
      std::transform(key.begin(), key.end(), key.begin(), ::tolower);

      headers[key] = val;

      if (key == "content-length")
      {
        std::from_chars(val.data(), val.data() + val.size(), _expectedBodySize);
        if (_expectedBodySize > 0)
        {
          body.reserve(std::min(_expectedBodySize, size_t{128} * 1024));
        }
      }
      from = to + 2;
    }
    return false;
  }

  static std::string trim(std::string str)
  {
    str.erase(str.find_last_not_of(' ') + 1);
    str.erase(0, str.find_first_not_of(' '));
    return str;
  }

  std::vector<uint8_t> _raw;
  size_t _expectedBodySize = 0;
  bool _headerReceived = false;
  bool _headerParsed = false;
};

} // namespace Netpp::Http
