#pragma once

#include <iostream>
#include <algorithm>
#include <charconv>
#include <map>
#include <memory>
#include <string>

#include "Netpp/Http/HttpException.h"
#include "Netpp/Http/HttpRequest.h"
#include "Netpp/Http/HttpResponse.h"
#include "Netpp/Protocol.h"
#include "Netpp/Socket.h"

namespace Netpp
{

namespace Http
{

class HttpProtocol: public Protocol
{
public:
    virtual ~HttpProtocol() {}

    virtual Status onConnect(sock_t s)
    {
        _requests[s] = std::make_shared<HttpRequest>();
        std::string ip = std::move(Socket::getpeername(s));
        std::cout << "[HTTP] " << ip << " connected\n";
        return Protocol::OK;
    }

    virtual Status onDisconnect(sock_t s)
    {
        _requests.erase(s);
        std::string ip = std::move(Socket::getpeername(s));
        std::cout << "[HTTP] " << ip << " disconnected\n";
        return Protocol::OK;
    }

    virtual Status onReceive(sock_t s)
    {
        char buff[1024];
        ssize_t len = Socket::recv(s, buff, sizeof(buff), 0);

        if(len < 0)
        {
            std::cout << "[HTTP] data error: " << len << " " << errno << "\n";
            if (errno == EAGAIN || errno == EWOULDBLOCK) return Protocol::OK;
            return Protocol::ERROR;
        }

        if(len == 0)
        {
            return Protocol::CLOSE;
        }

        std::cout << std::string(buff, len);

        std::shared_ptr<HttpRequest> req = _requests[s];
        try
        {
            req->receive(buff, len);

            if(req->headerParsed() && req->bodyReceived())
            {
                const char * content = "<html>\n<head><title>Not Found</title></head>\n<body><h1>Not Found</h1></body>\n</html>\n";
                size_t len = strlen(content);
                sendHeaders(s, req, 404, len);
                sendBody(s, content, len);
            }
        }
        catch(const HttpException& e)
        {
            const char * content = "<html>\n<head><title>Invalid request</title></head>\n<body><h1>Invalid Request</h1></body>\n</html>\n";
            size_t len = strlen(content);
            sendHeaders(s, req, e.code(), len);
            sendBody(s, content, len);
            return Protocol::CLOSE;
        }
        return Protocol::OK;
    }

private:
    void sendHeaders(sock_t s, std::shared_ptr<HttpRequest> req, int status, size_t len)
    {
        HttpResponse res;
        res.status = status;
        res.version = req->version;
        res.headers["content-type"] = "text/html";
        res.headers["content-length"] = std::to_string(len);
        const std::string headers = res.str();
        ssize_t slen = Socket::send(s, headers.c_str(), headers.size(), 0);
        std::cout << "[HTTP] sent headers " << slen << ' ' << errno << ' ' << strerror(errno) << "\n";
    }

    void sendBody(sock_t s, const char * content, size_t len)
    {
        ssize_t slen = Socket::send(s, content, len, 0);
        std::cout << "[HTTP] sent body " << slen << ' ' << errno << ' ' << strerror(errno) << "\n";
    }

    std::map<sock_t, std::shared_ptr<HttpRequest>> _requests;
};


}

}