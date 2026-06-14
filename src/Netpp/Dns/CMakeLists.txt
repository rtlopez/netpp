add_library(netpp_dns STATIC DnsParser.cpp)
target_include_directories(netpp_dns PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(netpp_dns PUBLIC netpp_core netpp_logger)
