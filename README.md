# Netpp

C++ networking library educational demo

## Features

* Event loop (epoll)
* Tcp client/server
* Http client/server
* Udp client/server
* Echo client/server
* Dns client
* CMake build

## HTTP Server example

```cpp
  Netpp::EventLoop loop;
  Netpp::Core::ThreadPollDispatcher dispatcher; // route data to thread workers
  Netpp::Core::TcpHandler tcp{&loop, &dispatcher}; // handle tcp sockets events

  Netpp::Http::HttpProtocol http(&tcp); // protocol handler

  tcp.listen("127.0.0.1", 1234, &http); // bind protocol to port

  loop.run(); // run processing loop

  dispatcher.stop(); // join threads before destroing objects
```

## Chat and Echo server example

```cpp
  Netpp::EventLoop loop;
  Netpp::Core::SingleThreadDispatcher dispatcher;
  Netpp::Core::TcpHandler tcp{&loop, &dispatcher};

  Netpp::Chat::ChatProtocol chat{&tcp};
  Netpp::Echo::EchoProtocol echo(&tcp);

  tcp.listen("127.0.0.1", 1235, &chat);
  tcp.listen("127.0.0.1", 1236, &echo);

  loop.run();
  dispatcher.stop();
```

# Configuring and Building

```bash
# Configure the project
cmake -S . -B ./build

# specify compiler and build type
cmake -S . -B ./build/ -D CMAKE_BUILD_TYPE=Debug -D CMAKE_CXX_COMPILER=clang

# Build all targets
cmake --build ./build

# Build server example only
cmake --build ./build -t server

# clean
cmake --build ./build -t clean

# Run unit tests
ctest --test-dir ./build

# Run integration tests
python3 src/server_test.py
```

## Todo

* Unit tests
* Config file
* more logger sinks

# Licence

This project is distributed under MIT Licence.

