#pragma once

#include <string>

#include "MoveOnlyFunction.h"

namespace Netpp
{

/// Abstract interface for asynchronous name resolution.
/// Implementations (e.g. DnsProtocol) invoke the callback from the event loop
/// when resolution completes — never blocking the caller.
class Resolver
{
public:
  using Callback = MoveOnlyFunction<void(const std::string &resolvedIp)>;

  virtual ~Resolver() = default;

  /// Resolve a hostname to an IP address string asynchronously.
  /// On success, callback is invoked with the resolved IP (e.g. "93.184.216.34").
  /// On failure, callback is invoked with an empty string.
  virtual void resolve(const std::string &host, Callback callback) = 0;
};

} // namespace Netpp
