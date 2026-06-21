#include "Netpp/Http/ChunkedEncoder.h"
#include <gtest/gtest.h>
#include <string>

using Netpp::DataEvent;
using Netpp::EventType;
using Netpp::Http::ChunkedEncoder;

namespace
{

std::string bufToStr(const DataEvent::Buffer &buf)
{
  return {buf.begin(), buf.end()};
}

DataEvent::Buffer strToBuf(const std::string &s)
{
  return {s.begin(), s.end()};
}

} // namespace

TEST(ChunkedEncoderTest, SingleDataChunkThenDone)
{
  int call = 0;
  ChunkedEncoder enc([&call]() -> DataEvent {
    call++;
    if (call == 1)
    {
      return {.buffer = strToBuf("hello"), .eventType = EventType::DATA};
    }
    return {.buffer = {}, .eventType = EventType::DONE};
  });

  auto e1 = enc();
  EXPECT_EQ(e1.eventType, EventType::DATA);
  EXPECT_EQ(bufToStr(e1.buffer), "5\r\nhello\r\n");

  auto e2 = enc();
  EXPECT_EQ(e2.eventType, EventType::DONE);
  EXPECT_EQ(bufToStr(e2.buffer), "0\r\n\r\n");
}

TEST(ChunkedEncoderTest, MultipleDataChunksThenDone)
{
  int call = 0;
  ChunkedEncoder enc([&call]() -> DataEvent {
    call++;
    if (call <= 3)
    {
      std::string data = "chunk" + std::to_string(call);
      return {.buffer = strToBuf(data), .eventType = EventType::DATA};
    }
    return {.buffer = {}, .eventType = EventType::DONE};
  });

  auto e1 = enc();
  EXPECT_EQ(e1.eventType, EventType::DATA);
  EXPECT_EQ(bufToStr(e1.buffer), "6\r\nchunk1\r\n");

  auto e2 = enc();
  EXPECT_EQ(e2.eventType, EventType::DATA);
  EXPECT_EQ(bufToStr(e2.buffer), "6\r\nchunk2\r\n");

  auto e3 = enc();
  EXPECT_EQ(e3.eventType, EventType::DATA);
  EXPECT_EQ(bufToStr(e3.buffer), "6\r\nchunk3\r\n");

  auto e4 = enc();
  EXPECT_EQ(e4.eventType, EventType::DONE);
  EXPECT_EQ(bufToStr(e4.buffer), "0\r\n\r\n");
}

TEST(ChunkedEncoderTest, DoneWithDataIncludesTerminator)
{
  ChunkedEncoder enc([]() -> DataEvent { return {.buffer = strToBuf("final"), .eventType = EventType::DONE}; });

  auto e = enc();
  EXPECT_EQ(e.eventType, EventType::DONE);
  EXPECT_EQ(bufToStr(e.buffer), "5\r\nfinal\r\n0\r\n\r\n");
}

TEST(ChunkedEncoderTest, DoneWithEmptyBuffer)
{
  ChunkedEncoder enc([]() -> DataEvent { return {.buffer = {}, .eventType = EventType::DONE}; });

  auto e = enc();
  EXPECT_EQ(e.eventType, EventType::DONE);
  EXPECT_EQ(bufToStr(e.buffer), "0\r\n\r\n");
}

TEST(ChunkedEncoderTest, NonDataEventPassesThrough)
{
  ChunkedEncoder enc([]() -> DataEvent { return {.buffer = strToBuf("ignored"), .eventType = EventType::DISCONNECT}; });

  auto e = enc();
  EXPECT_EQ(e.eventType, EventType::DISCONNECT);
  EXPECT_EQ(bufToStr(e.buffer), "ignored");
}

TEST(ChunkedEncoderTest, ErrorEventPassesThrough)
{
  ChunkedEncoder enc([]() -> DataEvent { return {.buffer = {}, .eventType = EventType::ERROR}; });

  auto e = enc();
  EXPECT_EQ(e.eventType, EventType::ERROR);
  EXPECT_TRUE(e.buffer.empty());
}

TEST(ChunkedEncoderTest, HexEncodingLargeChunk)
{
  std::string data(255, 'x');
  ChunkedEncoder enc([&data]() -> DataEvent { return {.buffer = strToBuf(data), .eventType = EventType::DONE}; });

  auto e = enc();
  EXPECT_EQ(e.eventType, EventType::DONE);
  std::string expected = "ff\r\n" + data + "\r\n0\r\n\r\n";
  EXPECT_EQ(bufToStr(e.buffer), expected);
}

TEST(ChunkedEncoderTest, HexEncoding4096Bytes)
{
  std::string data(4096, 'a');
  ChunkedEncoder enc([&data]() -> DataEvent { return {.buffer = strToBuf(data), .eventType = EventType::DATA}; });

  auto e = enc();
  EXPECT_EQ(e.eventType, EventType::DATA);
  std::string expected = "1000\r\n" + data + "\r\n";
  EXPECT_EQ(bufToStr(e.buffer), expected);
}

TEST(ChunkedEncoderTest, WrapStaticHelper)
{
  int call = 0;
  auto gen = ChunkedEncoder::wrap([&call]() -> DataEvent {
    call++;
    if (call == 1)
    {
      return {.buffer = strToBuf("hi"), .eventType = EventType::DATA};
    }
    return {.buffer = {}, .eventType = EventType::DONE};
  });

  auto e1 = gen();
  EXPECT_EQ(e1.eventType, EventType::DATA);
  EXPECT_EQ(bufToStr(e1.buffer), "2\r\nhi\r\n");

  auto e2 = gen();
  EXPECT_EQ(e2.eventType, EventType::DONE);
  EXPECT_EQ(bufToStr(e2.buffer), "0\r\n\r\n");
}
