#include <signal.h>
#include <iostream>

#include "Netpp/EventLoopEpoll.h"
#include "Netpp/TcpServer.h"
#include "Netpp/Http/HttpProtocol.h"

void sigpipe_handler(int signum)
{
    printf("Caught signal SIGPIPE %d\n",signum);
}

int main()
{
    ::signal(SIGPIPE, sigpipe_handler);

    Netpp::EventLoopEpoll loop;
    Netpp::Http::HttpProtocol protocol;
    Netpp::TcpServer tcpServer{"127.0.0.1", 1234, &loop, &protocol};
    loop.run();

    return 0;
}
