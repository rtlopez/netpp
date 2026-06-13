cmake_minimum_required(VERSION 3.14)

project(Netpp VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g")
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

set(NETPP_LIBS
    lyra
    Threads::Threads
    netpp_core
    netpp_logger
    netpp_http
    netpp_echo
    netpp_chat
)

# server example
add_executable(server src/server.cpp)
target_link_libraries(server PRIVATE ${NETPP_LIBS})
target_link_options(server PRIVATE -rdynamic)

# tcp client example
add_executable(client src/client.cpp)
target_link_libraries(client PRIVATE ${NETPP_LIBS})

# http client example
add_executable(http_client src/http_client.cpp)
target_link_libraries(http_client PRIVATE ${NETPP_LIBS})

## unit tests
## https://cliutils.gitlab.io/modern-cmake/testing/

#if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    include(CTest)
#endif()

#if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)
    add_subdirectory(tests)
#endif()
