#include <iostream>

#include "Netpp.h"

int main()
{
    using namespace Netpp;

    auto onRecv = [](sock_t s) -> TcpServer::Status {
        char buff[1024];
        ssize_t len = recv(s, buff, sizeof(buff), 0);

        if(len < 0)
        {
            std::cout << "* data error: " << len << " " << errno << "\n";
            if (errno == EAGAIN) return TcpServer::OK;
            return TcpServer::ERROR;
        }

        if(len == 0)
        {
            std::cout << "* empty data\n";
            return TcpServer::CLOSE;
        }

        buff[len] = '\0';
        if(buff[len - 1] == '\n') buff[len - 1] = '\0';
        if(buff[len - 2] == '\r') buff[len - 2] = '\0';
        
        std::cout << "* new data: " << buff << "\n";

        return TcpServer::OK;
    };

    auto onConn = [](sock_t s) -> TcpServer::Status {
        std::string ip = std::move(Socket::getpeername(s));
        std::cout << "* conn accept: " << ip << "\n";
        return TcpServer::OK;
    };

    auto onClose = [](sock_t s) -> TcpServer::Status {
        std::string ip = std::move(Socket::getpeername(s));
        std::cout << "* conn close: " << ip << "\n";
        return TcpServer::OK;
    };

    TcpServer tcpServer{"127.0.0.1", 1234, onRecv, onConn, onClose};

    Epoll epoll{tcpServer};

    epoll.init();
    epoll.run();

    return 0;
}
