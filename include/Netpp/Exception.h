#pragma once

#include <stdexcept>
#include <cstring>

namespace Netpp
{

class ErrnoException: public std::runtime_error
{
public:
    ErrnoException(int erno, const std::string& msg): std::runtime_error(msg), _msg(msg), _errno(erno)
    {
        _msg += ": (";
        _msg += std::to_string(errNo());
        _msg += ") ";
        _msg += errStr();
    }
    int errNo() const
    {
        return _errno;
    }
    const char * errStr() const
    {
        return std::strerror(_errno);
    }
    virtual const char * what() const noexcept override
    {
        return _msg.c_str();
    }
private:
    std::string _msg;
    int _errno;
};

class SocketException: public ErrnoException
{
public:
    SocketException(int eno, const std::string& msg): ErrnoException(eno, msg) {}
};

class EventLoopException: public ErrnoException
{
public:
    EventLoopException(int eno, const std::string& msg): ErrnoException(eno, msg) {}
};

}
