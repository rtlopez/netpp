add_library(netpp_core STATIC Core.cpp)
target_include_directories(netpp_core PUBLIC ${PROJECT_SOURCE_DIR}/include)

add_subdirectory(Logger)
add_subdirectory(Http)
add_subdirectory(Echo)
add_subdirectory(Chat)
add_subdirectory(Dns)
