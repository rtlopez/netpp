#include <signal.h>
#include <iostream>
#include "Netpp.h"

void sigpipe_handler(int signum)
{
    printf("Caught signal SIGPIPE %d\n",signum);
}

int main()
{
    using namespace Netpp;

    ::signal(SIGPIPE, sigpipe_handler);

    EventLoopEpoll loop;
    HttpProtocol protocol;
    TcpServer tcpServer{"127.0.0.1", 1234, &loop, &protocol};
    loop.run();

     return 0;
}
