cmake_minimum_required(VERSION 3.14)

project(Netpp VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g")
add_compile_options(-Wall -Wextra)

# --- Sanitizers ---

# Option A: explicit sanitizer selection via -DNETPP_SANITIZER=address,undefined
set(NETPP_SANITIZER "" CACHE STRING "Enable sanitizer (address, thread, undefined, memory, leak)")

if(NETPP_SANITIZER)
    add_compile_options(-fsanitize=${NETPP_SANITIZER} -fno-omit-frame-pointer)
    add_link_options(-fsanitize=${NETPP_SANITIZER})
endif()

# Option B: custom build types (use via -DCMAKE_BUILD_TYPE=ASan / TSan / UBSan)
set(CMAKE_CXX_FLAGS_ASAN "-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer" CACHE STRING "")
set(CMAKE_EXE_LINKER_FLAGS_ASAN "-fsanitize=address,undefined" CACHE STRING "")
set(CMAKE_SHARED_LINKER_FLAGS_ASAN "-fsanitize=address,undefined" CACHE STRING "")

set(CMAKE_CXX_FLAGS_TSAN "-O1 -g -fsanitize=thread -fno-omit-frame-pointer" CACHE STRING "")
set(CMAKE_EXE_LINKER_FLAGS_TSAN "-fsanitize=thread" CACHE STRING "")
set(CMAKE_SHARED_LINKER_FLAGS_TSAN "-fsanitize=thread" CACHE STRING "")

set(CMAKE_CXX_FLAGS_UBSAN "-O1 -g -fsanitize=undefined -fno-omit-frame-pointer" CACHE STRING "")
set(CMAKE_EXE_LINKER_FLAGS_UBSAN "-fsanitize=undefined" CACHE STRING "")
set(CMAKE_SHARED_LINKER_FLAGS_UBSAN "-fsanitize=undefined" CACHE STRING "")

include_directories(include/)

include(FetchContent)
FetchContent_Declare(
    lyra
    GIT_REPOSITORY https://github.com/bfgroup/Lyra.git
    GIT_TAG 1.8.0
)

FetchContent_Declare(
    ada
    GIT_REPOSITORY https://github.com/ada-url/ada.git
    GIT_TAG v3.2.4
)
set(ADA_TESTING OFF CACHE BOOL "" FORCE)
set(ADA_BENCHMARKS OFF CACHE BOOL "" FORCE)
set(ADA_TOOLS OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(lyra ada)

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
    netpp_dns
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

# dns client example
add_executable(dns_client src/dns_client.cpp)
target_link_libraries(dns_client PRIVATE ${NETPP_LIBS})

## unit tests
## https://cliutils.gitlab.io/modern-cmake/testing/

#if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    include(CTest)
#endif()

#if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)
    add_subdirectory(tests)
#endif()
