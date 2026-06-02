add_library(netpp_chat STATIC ChatProtocol.cpp)
target_include_directories(netpp_chat PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(netpp_chat PUBLIC netpp_core netpp_logger)
