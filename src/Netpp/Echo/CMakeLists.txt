add_library(netpp_echo STATIC EchoProtocol.cpp)
target_include_directories(netpp_echo PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(netpp_echo PUBLIC netpp_core netpp_logger)
