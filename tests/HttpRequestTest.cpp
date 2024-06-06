#include <gtest/gtest.h>
#include "Netpp/Http/HttpRequest.h"

TEST(HttpRequestTest, ParseWithoutBody)
{
  Netpp::Http::HttpRequest req;

  const char data[] = "GET / HTTP/1.0\r\n"
    "Content-Length: 0\r\n"
    "\r\n"
  ;

  req.receive(data, sizeof(data) - 1);

  EXPECT_TRUE(req.headerReceived());
  EXPECT_TRUE(req.headerParsed());
  EXPECT_TRUE(req.bodyReceived());

  EXPECT_EQ(req.method, "GET");
  EXPECT_EQ(req.path, "/");
  EXPECT_EQ(req.version, "1.0");

  EXPECT_EQ(req.body.size(), 0);
}

TEST(HttpRequestTest, ParseWithBody)
{
  Netpp::Http::HttpRequest req;

  const char data[] = "GET / HTTP/1.0\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: 2\r\n"
    "\r\n"
    "{}"
  ;

  req.receive(data, sizeof(data) - 1);

  EXPECT_TRUE(req.headerReceived());
  EXPECT_TRUE(req.headerParsed());
  EXPECT_TRUE(req.bodyReceived());

  EXPECT_EQ(req.method, "GET");
  EXPECT_EQ(req.path, "/");
  EXPECT_EQ(req.version, "1.0");

  EXPECT_EQ(req.body.size(), 2);
}

int main(int argc, char **argv)
{
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
