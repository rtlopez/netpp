#pragma once

#include <iostream>

#if 1
namespace
{

template <typename T>
void debug(T last)
{
  std::cout << last << "\n";
}

template <typename T, typename... Args>
void debug(T first, Args... rest)
{
  std::cout << first << " ";
  debug(rest...);
}

} // namespace
#else
#define debug(...)
#endif
