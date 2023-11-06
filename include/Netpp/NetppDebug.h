#pragma once

#include <iostream>

#if 0
namespace {

template<typename T>
void debug(T last)
{
    std::cout << last << "\n";
}

template<typename T, typename... Args>
void debug(T first, Args... args)
{
    std::cout << first << " ";
    debug(args...);
}

}
#else
#define debug(...)
#endif
