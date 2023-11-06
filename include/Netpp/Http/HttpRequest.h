#pragma once

#include <algorithm>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "Netpp/Http/HttpException.h"

namespace Netpp
{

namespace Http
{

class HttpRequest
{
    enum State {
        PARSE_METHOD,
        PARSE_PATH,
        PARSE_VERSION,
        PARSE_HEADERS,
        PARSE_DONE,
    };
public:
    std::string method;
    std::string path;
    std::string version;
    std::map<std::string, std::string> headers;
    std::vector<char> header;
    std::vector<char> body;

    void receive(const char * c, size_t len)
    {
        if(!len) return;
        if(!_headerReceived)
        {
            std::string s{c, len};
            size_t pos = s.find("\r\n\r\n");
            if(!header.size()) header.reserve(1024);
            if(pos == std::string::npos)
            {
                std::copy(c, c + len, std::back_inserter(header));
            }
            else
            {
                std::copy(c, c + pos + 4, std::back_inserter(header));
                _headerReceived = true;
                if(!parse())
                {
                    throw HttpException(400);
                }
                if(pos + 4 < len)
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

    bool parse()
    {
        State state = PARSE_METHOD;
        std::string s{header.begin(), header.end()};
        size_t from = 0;
        while(true)
        {
            switch(state)
            {
                case PARSE_METHOD: {
                    size_t to = s.find(' ', from);
                    if(to == std::string::npos) return false;
                    method = s.substr(from, to - from);
                    from = to + 1;
                    state = PARSE_PATH;
                    break;
                }
                case PARSE_PATH: {
                    size_t to = s.find(' ', from);
                    if(to == std::string::npos) return false;
                    path = s.substr(from, to - from);
                    from = to + 6; // skip " HTTP/" fragment
                    state = PARSE_VERSION;
                    break;
                }
                case PARSE_VERSION: {
                    size_t to = s.find("\r\n", from);
                    if(to == std::string::npos) return false;
                    version = s.substr(from, to - from);
                    from = to + 2;
                    state = PARSE_HEADERS;
                    break;
                }
                case PARSE_HEADERS: {
                    size_t to = s.find("\r\n", from);
                    if(to == std::string::npos) return false;
                    if(from == to)
                    {
                        state = PARSE_DONE;
                        _headerParsed = true;
                        break;
                    }
                    std::string line = s.substr(from, to - from);
                    size_t cto = line.find(':');
                    if(cto == std::string::npos) return false;
                    std::string key = trim(line.substr(0, cto));
                    std::string val = trim(line.substr(cto + 1));
                    std::transform(key.begin(), key.end(), key.begin(), ::tolower);
                    headers[key] = val;
                    if(key == "content-length")
                    {
                        std::from_chars(val.data(), val.data() + val.size(), _expectedBodySize);
                        if(_expectedBodySize > 0) body.reserve(std::min(_expectedBodySize, 128ul * 1024));
                    }
                    from = to + 2;
                    break;
                }
                case PARSE_DONE:
                    return true;
                    break;
            }
        }
        return false;
    }

    const std::string str() const
    {
        std::ostringstream ss;

        ss << method << ' ' << path << " HTTP/" << version << "\r\n";
        for(auto [key, val]: headers)
        {
            ss << key << ": " << val << "\r\n";
        }
        ss << "\r\n";

        return ss.str();
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
        return body.size() == _expectedBodySize;
    }
private:
    size_t _expectedBodySize = 0;
    bool _headerReceived = false;
    bool _headerParsed = false;

    static std::string trim(std::string str)
    {
        str.erase(str.find_last_not_of(' ') + 1); // suffixing spaces
        str.erase(0, str.find_first_not_of(' ')); // prefixing spaces
        return str;
    }
};

}

}
