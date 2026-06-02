add_library(netpp_http STATIC HttpProtocol.cpp)
target_include_directories(netpp_http PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(netpp_http PUBLIC netpp_core netpp_logger)
