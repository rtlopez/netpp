
include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(HttpMessageTest HttpMessageTest.cpp)
target_link_libraries(HttpMessageTest GTest::gtest_main netpp_logger)

add_executable(RingBufferTest RingBufferTest.cpp)
target_link_libraries(RingBufferTest GTest::gtest_main)

add_executable(DnsParserTest DnsParserTest.cpp)
target_link_libraries(DnsParserTest GTest::gtest_main netpp_dns)

include(GoogleTest)
gtest_discover_tests(HttpMessageTest)
gtest_discover_tests(RingBufferTest)
gtest_discover_tests(DnsParserTest)
