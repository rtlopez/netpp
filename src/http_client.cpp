#include <iostream>
#include <string>

#include "Netpp/Http/HttpClientProtocol.h"
#include "Netpp/Stack.h"

int main(int argc, char *argv[])
{
  const char *host = argc > 1 ? argv[1] : "127.0.0.1";
  uint16_t port = argc > 2 ? static_cast<uint16_t>(std::stoi(argv[2])) : 80;
  const char *path = argc > 3 ? argv[3] : "/";

  Netpp::Stack stack({.logLevel = Netpp::Logger::LogLevel::DEBUG});

  // Issue GET request - returns std::future<HttpResponse>
  auto future = stack.httpClient().get(host, port, path);

  // Run event loop to process the request
  // Block until the response arrives (or timeout)
  stack.run();

  try
  {
    auto response = future.get();
    std::cout << response.str() << "\n";
    std::cout.write(reinterpret_cast<const char *>(response.body.data()), response.body.size());
    std::cout << "\n";
  }
  catch (const std::exception &e)
  {
    std::cerr << "request failed: " << e.what() << "\n";
  }

  return 0;
}
