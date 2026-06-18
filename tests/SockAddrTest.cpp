#include "Netpp/SockAddr.h"
#include <gtest/gtest.h>

#include <cstring>

using Netpp::SockAddr;

// ── Default construction ────────────────────────────────────────────

TEST(SockAddrTest, DefaultConstructedIsEmpty)
{
  SockAddr sa;
  EXPECT_EQ(sa.family(), 0);
  EXPECT_EQ(sa.len(), 0u);
  EXPECT_EQ(sa.toString(), "(unknown)");
}

// ── IPv4 from() ─────────────────────────────────────────────────────

TEST(SockAddrTest, FromIPv4)
{
  auto sa = SockAddr::from("192.168.1.100", 8080);
  EXPECT_EQ(sa.family(), AF_INET);
  EXPECT_EQ(sa.port(), 8080);
  EXPECT_EQ(sa.len(), sizeof(sockaddr_in));
}

TEST(SockAddrTest, FromIPv4Loopback)
{
  auto sa = SockAddr::from("127.0.0.1", 0);
  EXPECT_EQ(sa.family(), AF_INET);
  EXPECT_EQ(sa.port(), 0);
}

TEST(SockAddrTest, FromIPv4Any)
{
  auto sa = SockAddr::from("0.0.0.0", 443);
  EXPECT_EQ(sa.family(), AF_INET);
  EXPECT_EQ(sa.port(), 443);
}

TEST(SockAddrTest, FromIPv4InvalidThrows)
{
  EXPECT_THROW(SockAddr::from("999.999.999.999", 80), std::invalid_argument);
  EXPECT_THROW(SockAddr::from("not-an-address", 80), std::invalid_argument);
  EXPECT_THROW(SockAddr::from("", 80), std::invalid_argument);
}

// ── IPv6 from() ─────────────────────────────────────────────────────

TEST(SockAddrTest, FromIPv6Loopback)
{
  auto sa = SockAddr::from("::1", 9090);
  EXPECT_EQ(sa.family(), AF_INET6);
  EXPECT_EQ(sa.port(), 9090);
  EXPECT_EQ(sa.len(), sizeof(sockaddr_in6));
}

TEST(SockAddrTest, FromIPv6Any)
{
  auto sa = SockAddr::from("::", 0);
  EXPECT_EQ(sa.family(), AF_INET6);
  EXPECT_EQ(sa.port(), 0);
}

TEST(SockAddrTest, FromIPv6Full)
{
  auto sa = SockAddr::from("fe80::1", 1234);
  EXPECT_EQ(sa.family(), AF_INET6);
  EXPECT_EQ(sa.port(), 1234);
}

TEST(SockAddrTest, FromIPv6MappedIPv4)
{
  auto sa = SockAddr::from("::ffff:192.168.0.1", 80);
  EXPECT_EQ(sa.family(), AF_INET6);
  EXPECT_EQ(sa.port(), 80);
}

TEST(SockAddrTest, FromIPv6InvalidThrows)
{
  EXPECT_THROW(SockAddr::from("::gggg", 80), std::invalid_argument);
}

// ── toString() ──────────────────────────────────────────────────────

TEST(SockAddrTest, ToStringIPv4)
{
  auto sa = SockAddr::from("10.0.0.1", 3000);
  EXPECT_EQ(sa.toString(), "10.0.0.1:3000");
}

TEST(SockAddrTest, ToStringIPv4Any)
{
  auto sa = SockAddr::from("0.0.0.0", 80);
  EXPECT_EQ(sa.toString(), "0.0.0.0:80");
}

TEST(SockAddrTest, ToStringIPv6Loopback)
{
  auto sa = SockAddr::from("::1", 443);
  EXPECT_EQ(sa.toString(), "[::1]:443");
}

TEST(SockAddrTest, ToStringIPv6Any)
{
  auto sa = SockAddr::from("::", 8080);
  EXPECT_EQ(sa.toString(), "[::]:8080");
}

TEST(SockAddrTest, ToStringIPv6Full)
{
  auto sa = SockAddr::from("2001:db8::1", 53);
  EXPECT_EQ(sa.toString(), "[2001:db8::1]:53");
}

// ── port() ──────────────────────────────────────────────────────────

TEST(SockAddrTest, PortHighValue)
{
  auto sa = SockAddr::from("127.0.0.1", 65535);
  EXPECT_EQ(sa.port(), 65535);
}

TEST(SockAddrTest, PortZero)
{
  auto sa = SockAddr::from("::1", 0);
  EXPECT_EQ(sa.port(), 0);
}

// ── addr() and len() ───────────────────────────────────────────────

TEST(SockAddrTest, AddrNotNull)
{
  auto sa = SockAddr::from("127.0.0.1", 80);
  EXPECT_NE(sa.addr(), nullptr);

  const auto &csa = sa;
  EXPECT_NE(csa.addr(), nullptr);
}

TEST(SockAddrTest, AddrFamilyMatchesIPv4)
{
  auto sa = SockAddr::from("10.0.0.1", 80);
  EXPECT_EQ(sa.addr()->sa_family, AF_INET);
}

TEST(SockAddrTest, AddrFamilyMatchesIPv6)
{
  auto sa = SockAddr::from("::1", 80);
  EXPECT_EQ(sa.addr()->sa_family, AF_INET6);
}

// ── reset() ─────────────────────────────────────────────────────────

TEST(SockAddrTest, ResetSetsFullStorageLen)
{
  auto sa = SockAddr::from("127.0.0.1", 80);
  EXPECT_EQ(sa.len(), sizeof(sockaddr_in));

  sa.reset();
  EXPECT_EQ(sa.len(), sizeof(sockaddr_storage));
  EXPECT_EQ(sa.family(), 0);
}

// ── Copy semantics ──────────────────────────────────────────────────

TEST(SockAddrTest, CopyConstruct)
{
  auto sa = SockAddr::from("192.168.0.1", 5000);
  SockAddr copy = sa;

  EXPECT_EQ(copy.family(), AF_INET);
  EXPECT_EQ(copy.port(), 5000);
  EXPECT_EQ(copy.toString(), sa.toString());
}

TEST(SockAddrTest, CopyAssign)
{
  auto sa4 = SockAddr::from("10.0.0.1", 80);
  auto sa6 = SockAddr::from("::1", 443);

  sa4 = sa6;
  EXPECT_EQ(sa4.family(), AF_INET6);
  EXPECT_EQ(sa4.port(), 443);
  EXPECT_EQ(sa4.toString(), "[::1]:443");
}

// ── Construct from raw sockaddr ─────────────────────────────────────

TEST(SockAddrTest, ConstructFromRawIPv4)
{
  sockaddr_in raw{};
  raw.sin_family = AF_INET;
  raw.sin_port = htons(1234);
  ::inet_pton(AF_INET, "172.16.0.1", &raw.sin_addr);

  SockAddr sa(reinterpret_cast<const sockaddr *>(&raw), sizeof(raw));
  EXPECT_EQ(sa.family(), AF_INET);
  EXPECT_EQ(sa.port(), 1234);
  EXPECT_EQ(sa.toString(), "172.16.0.1:1234");
}

TEST(SockAddrTest, ConstructFromRawIPv6)
{
  sockaddr_in6 raw{};
  raw.sin6_family = AF_INET6;
  raw.sin6_port = htons(9999);
  ::inet_pton(AF_INET6, "fe80::42", &raw.sin6_addr);

  SockAddr sa(reinterpret_cast<const sockaddr *>(&raw), sizeof(raw));
  EXPECT_EQ(sa.family(), AF_INET6);
  EXPECT_EQ(sa.port(), 9999);
  EXPECT_EQ(sa.toString(), "[fe80::42]:9999");
}

// ── Mutable len() reference ─────────────────────────────────────────

TEST(SockAddrTest, MutableLenRef)
{
  SockAddr sa;
  sa.reset();
  socklen_t &ref = sa.len();
  // Simulate what accept()/recvfrom() would do: kernel writes actual len
  ref = sizeof(sockaddr_in);
  EXPECT_EQ(sa.len(), sizeof(sockaddr_in));
}
