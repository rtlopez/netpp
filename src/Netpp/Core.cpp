// Core translation unit for netpp_core static library.
#include <atomic>

static std::atomic<int> x = 5;

void foo()
{  
  ++x;
}