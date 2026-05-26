# Netpp

C++ networking library educational demo

## Features

* Event loop (epoll)
* Tcp server
* Echo server
* Http server
* CMake build

## HTTP Server example

```cpp
  Netpp::EventLoopEpoll loop;

  Netpp::Http::HttpProtocol http;

  Netpp::TcpServer httpServer{"127.0.0.1", 1234, &loop, &http};

  loop.run();
```

## Chat and Echo server example

```cpp
  Netpp::EventLoopEpoll loop;

  Netpp::Chat::ChatProtocol chat;
  Netpp::Echo::EchoProtocol echo;

  Netpp::TcpServer chatServer{"127.0.0.1", 1235, &loop, &chat};
  Netpp::TcpServer echoServer{"127.0.0.1", 1236, &loop, &echo};

  loop.run();
```

# Building

```bash
# Configure the project
cmake -S . -B ./build

# Build the project
cmake --build ./build

# Run unit tests
cd build && ctest

# Run integration tests
python3 src/server_test.py
```

## Todo

* Unit tests
* Config file
* Configurable logger

# Licence

This project is distributed under MIT Licence.

