#include "Netpp/Dns/DnsMessage.h"
#include "Netpp/Dns/DnsParser.h"
#include <gtest/gtest.h>

using namespace Netpp::Dns;

TEST(DnsParserTest, SerializeQuery)
{
  auto msg = DnsMessage::query("example.com", DnsType::A, 0x1234);
  auto wire = DnsParser::serialize(msg);

  // DNS header: 12 bytes
  // Question: \x07example\x03com\x00 (13) + type(2) + class(2) = 17
  EXPECT_EQ(wire.size(), 12 + 17);

  // Check ID
  EXPECT_EQ(wire[0], 0x12);
  EXPECT_EQ(wire[1], 0x34);

  // Flags: RD=1, rest=0 → 0x0100
  EXPECT_EQ(wire[2], 0x01);
  EXPECT_EQ(wire[3], 0x00);

  // QDCOUNT=1
  EXPECT_EQ(wire[4], 0x00);
  EXPECT_EQ(wire[5], 0x01);

  // ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
  for (int i = 6; i < 12; i++)
  {
    EXPECT_EQ(wire[i], 0x00);
  }

  // Name: \x07example\x03com\x00
  EXPECT_EQ(wire[12], 7);
  EXPECT_EQ(std::string(wire.begin() + 13, wire.begin() + 20), "example");
  EXPECT_EQ(wire[20], 3);
  EXPECT_EQ(std::string(wire.begin() + 21, wire.begin() + 24), "com");
  EXPECT_EQ(wire[24], 0);

  // QTYPE=A(1), QCLASS=IN(1)
  EXPECT_EQ(wire[25], 0x00);
  EXPECT_EQ(wire[26], 0x01);
  EXPECT_EQ(wire[27], 0x00);
  EXPECT_EQ(wire[28], 0x01);
}

TEST(DnsParserTest, RoundtripQuery)
{
  auto original = DnsMessage::query("test.example.org", DnsType::AAAA, 0xABCD);
  auto wire = DnsParser::serialize(original);
  auto parsed = DnsParser::parse(wire.data(), wire.size());

  EXPECT_EQ(parsed.header.id, 0xABCD);
  EXPECT_FALSE(parsed.header.qr);
  EXPECT_TRUE(parsed.header.rd);
  EXPECT_EQ(parsed.header.qdcount, 1);
  EXPECT_EQ(parsed.header.ancount, 0);

  ASSERT_EQ(parsed.questions.size(), 1);
  EXPECT_EQ(parsed.questions[0].name, "test.example.org");
  EXPECT_EQ(parsed.questions[0].type, DnsType::AAAA);
  EXPECT_EQ(parsed.questions[0].cls, DnsClass::IN);
}

TEST(DnsParserTest, ParseResponse)
{
  // Manually constructed DNS response for "example.com" → 93.184.216.34
  // Header
  std::vector<uint8_t> pkt = {
      0x12, 0x34, // ID
      0x81, 0x80, // QR=1, RD=1, RA=1
      0x00, 0x01, // QDCOUNT=1
      0x00, 0x01, // ANCOUNT=1
      0x00, 0x00, // NSCOUNT=0
      0x00, 0x00, // ARCOUNT=0
  };

  // Question: example.com A IN
  std::vector<uint8_t> qname = {0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00};
  pkt.insert(pkt.end(), qname.begin(), qname.end());
  pkt.push_back(0x00);
  pkt.push_back(0x01); // QTYPE=A
  pkt.push_back(0x00);
  pkt.push_back(0x01); // QCLASS=IN

  // Answer: pointer to name at offset 12 (0xC00C), A, IN, TTL=300, RDLENGTH=4, 93.184.216.34
  pkt.push_back(0xC0);
  pkt.push_back(0x0C); // name pointer to offset 12
  pkt.push_back(0x00);
  pkt.push_back(0x01); // TYPE=A
  pkt.push_back(0x00);
  pkt.push_back(0x01); // CLASS=IN
  pkt.push_back(0x00);
  pkt.push_back(0x00);
  pkt.push_back(0x01);
  pkt.push_back(0x2C); // TTL=300
  pkt.push_back(0x00);
  pkt.push_back(0x04); // RDLENGTH=4
  pkt.push_back(93);
  pkt.push_back(184);
  pkt.push_back(216);
  pkt.push_back(34); // RDATA

  auto msg = DnsParser::parse(pkt.data(), pkt.size());

  EXPECT_EQ(msg.header.id, 0x1234);
  EXPECT_TRUE(msg.header.qr);
  EXPECT_TRUE(msg.header.rd);
  EXPECT_TRUE(msg.header.ra);
  EXPECT_EQ(msg.header.rcode, DnsRCode::NoError);

  ASSERT_EQ(msg.questions.size(), 1);
  EXPECT_EQ(msg.questions[0].name, "example.com");

  ASSERT_EQ(msg.answers.size(), 1);
  EXPECT_EQ(msg.answers[0].name, "example.com");
  EXPECT_EQ(msg.answers[0].type, DnsType::A);
  EXPECT_EQ(msg.answers[0].ttl, 300);
  EXPECT_EQ(msg.answers[0].rdataAsIPv4(), "93.184.216.34");
}

TEST(DnsParserTest, ParseTooShort)
{
  std::vector<uint8_t> short_pkt = {0x00, 0x01, 0x02};
  EXPECT_THROW(DnsParser::parse(short_pkt.data(), short_pkt.size()), DnsParseError);
}

TEST(DnsParserTest, SerializeMultiLabelName)
{
  auto msg = DnsMessage::query("sub.domain.example.co.uk", DnsType::A, 1);
  auto wire = DnsParser::serialize(msg);
  auto parsed = DnsParser::parse(wire.data(), wire.size());

  ASSERT_EQ(parsed.questions.size(), 1);
  EXPECT_EQ(parsed.questions[0].name, "sub.domain.example.co.uk");
}

TEST(DnsParserTest, IPv6Record)
{
  DnsRecord r;
  r.type = DnsType::AAAA;
  r.rdata = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
  EXPECT_EQ(r.rdataAsIPv6(), "2001:db8::1");
}

int main(int argc, char **argv)
{
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
