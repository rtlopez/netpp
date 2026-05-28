#include "Netpp/RingBuffer.h"
#include <gtest/gtest.h>

#include <cstring>
#include <numeric>
#include <vector>

using Netpp::RingBuffer;

TEST(RingBufferTest, InitialState)
{
  RingBuffer buf(64);
  EXPECT_EQ(buf.size(), 0);
  EXPECT_EQ(buf.capacity(), 64);
  EXPECT_TRUE(buf.empty());
  EXPECT_TRUE(buf.readableSpan().empty());
}

TEST(RingBufferTest, WriteAndRead)
{
  RingBuffer buf(64);
  std::vector<uint8_t> data = {1, 2, 3, 4, 5};
  buf.write(data);

  EXPECT_EQ(buf.size(), 5);
  EXPECT_FALSE(buf.empty());

  auto span = buf.readableSpan();
  ASSERT_EQ(span.size(), 5);
  EXPECT_EQ(span[0], 1);
  EXPECT_EQ(span[4], 5);
}

TEST(RingBufferTest, PartialConsume)
{
  RingBuffer buf(64);
  std::vector<uint8_t> data = {10, 20, 30, 40, 50};
  buf.write(data);

  buf.consume(2);
  EXPECT_EQ(buf.size(), 3);

  auto span = buf.readableSpan();
  ASSERT_EQ(span.size(), 3);
  EXPECT_EQ(span[0], 30);
  EXPECT_EQ(span[1], 40);
  EXPECT_EQ(span[2], 50);
}

TEST(RingBufferTest, ConsumeAll)
{
  RingBuffer buf(64);
  std::vector<uint8_t> data = {1, 2, 3};
  buf.write(data);

  buf.consume(3);
  EXPECT_EQ(buf.size(), 0);
  EXPECT_TRUE(buf.empty());
  EXPECT_TRUE(buf.readableSpan().empty());
}

TEST(RingBufferTest, WrapAround)
{
  RingBuffer buf(8);

  // Fill 6 bytes, consume 4 -> head at 4, tail at 6, size=2
  std::vector<uint8_t> first = {1, 2, 3, 4, 5, 6};
  buf.write(first);
  buf.consume(4);
  EXPECT_EQ(buf.size(), 2);

  // Write 4 more bytes -> wraps around: tail goes to index 2
  std::vector<uint8_t> second = {7, 8, 9, 10};
  buf.write(second);
  EXPECT_EQ(buf.size(), 6);

  // readableSpan should return the contiguous segment from head to end
  auto span1 = buf.readableSpan();
  ASSERT_EQ(span1.size(), 4); // indices 4,5,6,7
  EXPECT_EQ(span1[0], 5);
  EXPECT_EQ(span1[1], 6);
  EXPECT_EQ(span1[2], 7);
  EXPECT_EQ(span1[3], 8);

  buf.consume(span1.size());

  // Next segment is the wrapped portion
  auto span2 = buf.readableSpan();
  ASSERT_EQ(span2.size(), 2);
  EXPECT_EQ(span2[0], 9);
  EXPECT_EQ(span2[1], 10);

  buf.consume(span2.size());
  EXPECT_TRUE(buf.empty());
}

TEST(RingBufferTest, AutoGrow)
{
  RingBuffer buf(4);
  std::vector<uint8_t> data(10);
  std::iota(data.begin(), data.end(), 1);

  buf.write(data);
  EXPECT_EQ(buf.size(), 10);
  EXPECT_GE(buf.capacity(), 10u);

  auto span = buf.readableSpan();
  ASSERT_EQ(span.size(), 10);
  for (size_t i = 0; i < 10; i++)
  {
    EXPECT_EQ(span[i], i + 1);
  }
}

TEST(RingBufferTest, AutoGrowWithExistingData)
{
  RingBuffer buf(8);

  // Create wrap-around scenario: write 6, consume 4, write 4 -> size=6, cap=8
  std::vector<uint8_t> a = {1, 2, 3, 4, 5, 6};
  buf.write(a);
  buf.consume(4);

  std::vector<uint8_t> b = {7, 8, 9, 10};
  buf.write(b);
  EXPECT_EQ(buf.size(), 6);

  // Now write more than available free space (2 bytes free) -> triggers grow
  std::vector<uint8_t> c = {11, 12, 13, 14, 15};
  buf.write(c);
  EXPECT_EQ(buf.size(), 11);

  // All data should be contiguous after grow+linearize
  auto span = buf.readableSpan();
  ASSERT_EQ(span.size(), 11);
  EXPECT_EQ(span[0], 5);
  EXPECT_EQ(span[1], 6);
  EXPECT_EQ(span[2], 7);
  EXPECT_EQ(span[10], 15);
}

TEST(RingBufferTest, Linearize)
{
  RingBuffer buf(8);

  std::vector<uint8_t> a = {1, 2, 3, 4, 5, 6};
  buf.write(a);
  buf.consume(4); // head=4, size=2

  std::vector<uint8_t> b = {7, 8, 9, 10};
  buf.write(b); // wraps around, size=6

  // Before linearize, readableSpan may not cover full size
  EXPECT_LT(buf.readableSpan().size(), buf.size());

  buf.linearize();

  // After linearize, full data accessible in one span
  auto span = buf.readableSpan();
  ASSERT_EQ(span.size(), 6);
  EXPECT_EQ(span[0], 5);
  EXPECT_EQ(span[5], 10);
}

TEST(RingBufferTest, WritableSpanAndCommit)
{
  RingBuffer buf(16);

  auto wspan = buf.writableSpan();
  ASSERT_GE(wspan.size(), 5u);

  // Write directly into the writable span
  uint8_t src[] = {100, 101, 102, 103, 104};
  std::memcpy(wspan.data(), src, 5);
  buf.commitWrite(5);

  EXPECT_EQ(buf.size(), 5);
  auto rspan = buf.readableSpan();
  ASSERT_EQ(rspan.size(), 5);
  EXPECT_EQ(rspan[0], 100);
  EXPECT_EQ(rspan[4], 104);
}

TEST(RingBufferTest, WritableSpanWhenFull)
{
  RingBuffer buf(4);
  std::vector<uint8_t> data = {1, 2, 3, 4};
  buf.write(data);

  auto wspan = buf.writableSpan();
  EXPECT_TRUE(wspan.empty());
}

TEST(RingBufferTest, ConsumeMoreThanSize)
{
  RingBuffer buf(8);
  std::vector<uint8_t> data = {1, 2, 3};
  buf.write(data);

  buf.consume(100); // should clamp to size
  EXPECT_EQ(buf.size(), 0);
  EXPECT_TRUE(buf.empty());
}

TEST(RingBufferTest, WriteEmptySpan)
{
  RingBuffer buf(8);
  std::span<const uint8_t> empty;
  buf.write(empty);
  EXPECT_EQ(buf.size(), 0);
}

TEST(RingBufferTest, SimulateSendLoop)
{
  RingBuffer buf(16);

  // Fill buffer with known pattern
  std::vector<uint8_t> data(20);
  std::iota(data.begin(), data.end(), 0);
  buf.write(data);

  // Simulate partial sends
  std::vector<uint8_t> received;
  while (!buf.empty())
  {
    auto span = buf.readableSpan();
    // Simulate send() consuming only 3 bytes at a time
    size_t sent = std::min(span.size(), size_t(3));
    received.insert(received.end(), span.begin(), span.begin() + sent);
    buf.consume(sent);
  }

  ASSERT_EQ(received.size(), 20);
  for (size_t i = 0; i < 20; i++)
  {
    EXPECT_EQ(received[i], i);
  }
}

TEST(RingBufferTest, LargeWrite)
{
  RingBuffer buf(8);

  std::vector<uint8_t> data(1024);
  std::iota(data.begin(), data.end(), 0);
  buf.write(data);

  EXPECT_EQ(buf.size(), 1024);
  EXPECT_GE(buf.capacity(), 1024u);

  auto span = buf.readableSpan();
  ASSERT_EQ(span.size(), 1024);
  for (size_t i = 0; i < 1024; i++)
  {
    EXPECT_EQ(span[i], static_cast<uint8_t>(i));
  }
}
