cmake_minimum_required(VERSION 3.10)

project(Netpp VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra)

include_directories(include/)

include(FetchContent)
FetchContent_Declare(
    lyra
    GIT_REPOSITORY https://github.com/bfgroup/Lyra.git
    GIT_TAG 1.8.0
)
FetchContent_MakeAvailable(lyra)

find_package(Threads REQUIRED)

add_subdirectory(src/Netpp)

# server example
add_executable(server src/server.cpp)
target_link_libraries(server PRIVATE
    lyra
    Threads::Threads
    netpp_core
    netpp_logger
    netpp_http
    netpp_echo
    netpp_chat
)

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
