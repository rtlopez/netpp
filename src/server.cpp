#include <iostream>

#include "Netpp.h"

int main()
{
    using namespace Netpp;

    EventLoopEpoll loop;
    ChatProtocol protocol;
    TcpServer tcpServer{"127.0.0.1", 1234, &loop, &protocol};

    loop.run();

    return 0;
}
