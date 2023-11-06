#pragma once

#include <algorithm>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace Netpp
{

namespace Http
{

class HttpResponse
{
public:
    std::string version = "0.9";
    int status = 200;
    std::map<std::string, std::string> headers;

    const std::string str() const
    {
        std::ostringstream ss;

        ss << "HTTP/" << version << ' ' << status << ' ' << codeToMessage(status) << "\r\n";
        for(auto [key, val]: headers)
        {
            ss << key << ": " << val << "\r\n";
        }
        ss << "\r\n";

        return ss.str();
    }

    static const char * codeToMessage(int code)
    {
        switch(code)
        {
            case 100: return "Continue";

            case 200: return "OK";
            case 201: return "Created";
            case 204: return "No Content";
            case 301: return "Moved Permanently";
            case 302: return "Found";
            case 304: return "Not Modified";

            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 405: return "Method Not Allowed";
            case 406: return "Not Acceptable";
            case 408: return "Request Timeout";
            case 410: return "Gone";
            case 411: return "Length Required";
            case 413: return "Payload Too Large";
            case 414: return "URI Too Long";
            case 415: return "Unsupported Media Type";
            case 429: return "Too Many Requests";

            case 500: return "Internal Server Error";
            case 501: return "Not Implemented";
            case 502: return "Bad Gateway";
            case 503: return "Service Unavailable";
            case 504: return "Gateway Timeout";
        }
        return "Unknown";
    }
};

}

}
