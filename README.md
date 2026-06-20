# Netpp

C++ networking library educational demo

## Features

* Event loop (epoll) with auto-stop on idle
* Tcp client/server
* Http client/server
* Udp client/server
* Echo client/server
* Dns client
* Stack facade (factory + dependency injection)
* CMake build

## Stack

`Netpp::Stack` is a facade that owns and lazily creates all infrastructure
(EventLoop, Dispatcher, TimerHandler, transports, protocols). Dependencies are
wired automatically on first access.

```cpp
// Config struct
Netpp::Stack stack({
    .dispatcherType = Netpp::StackConfig::DispatcherType::ThreadPool,
    .threadPoolSize = 8,
    .logLevel = Netpp::Logger::LogLevel::INFO,
});

// Or fluent builder
auto stack = Netpp::Stack::builder()
    .threadPool(8)
    .logLevel(Netpp::Logger::LogLevel::INFO)
    .build();
```

## HTTP Client example

```cpp
Netpp::Stack stack({.logLevel = Netpp::Logger::LogLevel::DEBUG});

auto future = stack.httpClient().get("example.com", 80, "/");

stack.run(); // blocks, auto-stops when connection closes

auto response = future.get();
std::cout << response.str() << "\n";
```

## DNS Client example

```cpp
Netpp::Stack stack({.dnsNameserver = "8.8.8.8"});

auto future = stack.dns().resolve("example.com", Netpp::Dns::DnsType::A);

stack.run(); // blocks, auto-stops when query completes

auto response = future.get();
for (auto &a : response.answers) {
    std::cout << a.name << " " << a.rdataString << "\n";
}
```

## HTTP Server example

```cpp
Netpp::Stack stack({
    .dispatcherType = Netpp::StackConfig::DispatcherType::ThreadPool,
    .threadPoolSize = 16,
});

auto &tcp = stack.tcp();

Netpp::Http::HttpProtocol http{&tcp};
Netpp::Http::HttpRouter router;

tcp.listen("127.0.0.1", 1234, &http);

http.addMiddleware([&router](auto &req, auto &res, auto conn) {
    router.handle(req, res, conn);
});

router.on("GET", "/", [](auto &, auto &res, auto) {
    res.setBody("<h1>Hello</h1>");
});

stack.run(); // blocks until signal (Ctrl+C)
```

## Chat and Echo server example

```cpp
Netpp::Stack stack;

auto &tcp = stack.tcp();

Netpp::Chat::ChatProtocol chat{&tcp};
Netpp::Echo::EchoProtocol echo{&tcp};

tcp.listen("127.0.0.1", 1235, &chat);
tcp.listen("127.0.0.1", 1236, &echo);

stack.run();
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
* Response read timeout
* Http improvements
  * keep-alive
  * chunked transfer encoding
  * compression gzip, (deflate, brotli)
  * static file server
  * vhosts routing and configuration
  * basic url rewrite
  * reverse proxy

# Licence

This project is distributed under MIT Licence.
