#pragma once

#include <string>

namespace Netpp
{

namespace Http
{

class HttpException
{
public:
    explicit HttpException(int code): _code(code) {}
    virtual const char * what() const noexcept
    {
        std::string msg{"Http Error "};
        msg += std::to_string(_code);
        return msg.c_str();
    }
    int code() const
    {
        return _code;
    }
private:
    int _code;
};

}

}
