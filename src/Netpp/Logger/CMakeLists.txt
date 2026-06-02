add_library(netpp_logger STATIC Logger.cpp)
target_include_directories(netpp_logger PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(netpp_logger PUBLIC netpp_core)
