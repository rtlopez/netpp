#include "Netpp/Http/HttpRequest.h"
#include "Netpp/Http/HttpResponse.h"
#include <gtest/gtest.h>

TEST(HttpMessageTest, RequestUninitializedState)
{
  Netpp::Http::HttpRequest req;

  EXPECT_FALSE(req.headerReceived());
  EXPECT_FALSE(req.headerParsed());
  EXPECT_FALSE(req.bodyReceived());
  EXPECT_FALSE(req.complete());

  EXPECT_TRUE(req.method.empty());
  EXPECT_TRUE(req.path.empty());
  EXPECT_TRUE(req.version.empty());
  EXPECT_TRUE(req.headers.empty());
  EXPECT_EQ(req.body.size(), 0);
}

TEST(HttpMessageTest, RequestParseWithoutBody)
{
  Netpp::Http::HttpRequest req;

  const char data[] = "GET / HTTP/1.0\r\n"
                      "Content-Length: 0\r\n"
                      "\r\n";

  req.receive(data, sizeof(data) - 1);

  EXPECT_TRUE(req.headerReceived());
  EXPECT_TRUE(req.headerParsed());
  EXPECT_TRUE(req.bodyReceived());

  EXPECT_EQ(req.method, "GET");
  EXPECT_EQ(req.path, "/");
  EXPECT_EQ(req.version, "1.0");

  EXPECT_EQ(req.body.size(), 0);
}

TEST(HttpMessageTest, RequestParseWithBody)
{
  Netpp::Http::HttpRequest req;

  const char data[] = "GET / HTTP/1.0\r\n"
                      "Content-Type: application/json\r\n"
                      "Content-Length: 2\r\n"
                      "\r\n"
                      "{}";

  req.receive(data, sizeof(data) - 1);

  EXPECT_TRUE(req.headerReceived());
  EXPECT_TRUE(req.headerParsed());
  EXPECT_TRUE(req.bodyReceived());

  EXPECT_EQ(req.method, "GET");
  EXPECT_EQ(req.path, "/");
  EXPECT_EQ(req.version, "1.0");

  EXPECT_EQ(req.body.size(), 2);
}

TEST(HttpMessageTest, ResponseUninitializedState)
{
  Netpp::Http::HttpResponse res;

  EXPECT_FALSE(res.headerReceived());
  EXPECT_FALSE(res.headerParsed());
  EXPECT_FALSE(res.bodyReceived());
  EXPECT_FALSE(res.complete());

  EXPECT_EQ(res.version, "0.9");
  EXPECT_EQ(res.status, 404);
  EXPECT_TRUE(res.headers.empty());
  EXPECT_EQ(res.body.size(), 0);
}

TEST(HttpMessageTest, ResponseParseWithoutBody)
{
  Netpp::Http::HttpResponse res;

  const char data[] = "HTTP/1.1 200 OK\r\n"
                      "Content-Type: text/html\r\n"
                      "Content-Length: 0\r\n"
                      "Connection: close\r\n"
                      "\r\n";

  res.receive(data, sizeof(data) - 1);

  EXPECT_TRUE(res.headerReceived());
  EXPECT_TRUE(res.headerParsed());
  EXPECT_TRUE(res.bodyReceived());
  EXPECT_TRUE(res.complete());

  EXPECT_EQ(res.version, "1.1");
  EXPECT_EQ(res.status, 200);
  EXPECT_EQ(res.headers["content-type"], "text/html");
  EXPECT_EQ(res.headers["connection"], "close");

  EXPECT_EQ(res.body.size(), 0);
}

TEST(HttpMessageTest, ResponseParseWithBody)
{
  Netpp::Http::HttpResponse res;

  const char data[] = "HTTP/1.1 404 Not Found\r\n"
                      "Content-Type: text/html\r\n"
                      "Content-Length: 13\r\n"
                      "\r\n"
                      "<h1>404</h1>\n";

  res.receive(data, sizeof(data) - 1);

  EXPECT_TRUE(res.headerReceived());
  EXPECT_TRUE(res.headerParsed());
  EXPECT_TRUE(res.bodyReceived());
  EXPECT_TRUE(res.complete());

  EXPECT_EQ(res.version, "1.1");
  EXPECT_EQ(res.status, 404);
  EXPECT_EQ(res.headers["content-type"], "text/html");

  EXPECT_EQ(res.body.size(), 13);
  std::string body(res.body.begin(), res.body.end());
  EXPECT_EQ(body, "<h1>404</h1>\n");
}

int main(int argc, char **argv)
{
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
