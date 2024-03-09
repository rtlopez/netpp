cmake_minimum_required(VERSION 3.10)

project(Netpp VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra)

include_directories(include/)

add_executable(server src/server.cpp)

add_executable(client src/client.cpp)
