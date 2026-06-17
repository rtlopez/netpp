#pragma once

namespace Netpp
{

using fd_t = int;

enum class LoopEventType
{
  READ,
  WRITE,
  ERROR,
};

} // namespace Netpp