cmake_minimum_required(VERSION 3.10)

project(Netpp VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra)

include_directories(include/)

# server example
add_executable(server src/server.cpp)

# client example
add_executable(client src/client.cpp)

## unit tests
## https://cliutils.gitlab.io/modern-cmake/chapters/testing.html

#if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    include(CTest)
#endif()

#if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)
    add_subdirectory(tests)
#endif()
