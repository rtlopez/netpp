#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace Netpp::Dns
{

// DNS record types (RFC 1035 + common extensions)
enum class DnsType : uint16_t
{
  A = 1,
  NS = 2,
  CNAME = 5,
  SOA = 6,
  PTR = 12,
  MX = 15,
  TXT = 16,
  AAAA = 28,
  SRV = 33,
};

// DNS record classes
enum class DnsClass : uint16_t
{
  IN = 1,
};

// DNS response codes
enum class DnsRCode : uint8_t
{
  NoError = 0,
  FormatError = 1,
  ServerFailure = 2,
  NameError = 3, // NXDOMAIN
  NotImplemented = 4,
  Refused = 5,
};

// DNS opcode values
enum class DnsOpCode : uint8_t
{
  Query = 0,
  IQuery = 1,
  Status = 2,
};

inline const char *rcodeToString(DnsRCode rcode)
{
  switch (rcode)
  {
  case DnsRCode::NoError:
    return "NoError";
  case DnsRCode::FormatError:
    return "FormatError";
  case DnsRCode::ServerFailure:
    return "ServerFailure";
  case DnsRCode::NameError:
    return "NameError";
  case DnsRCode::NotImplemented:
    return "NotImplemented";
  case DnsRCode::Refused:
    return "Refused";
  }
  return "Unknown";
}

inline const char *typeToString(DnsType type)
{
  switch (type)
  {
  case DnsType::A:
    return "A";
  case DnsType::NS:
    return "NS";
  case DnsType::CNAME:
    return "CNAME";
  case DnsType::SOA:
    return "SOA";
  case DnsType::PTR:
    return "PTR";
  case DnsType::MX:
    return "MX";
  case DnsType::TXT:
    return "TXT";
  case DnsType::AAAA:
    return "AAAA";
  case DnsType::SRV:
    return "SRV";
  }
  return "Unknown";
}

// DNS message header (RFC 1035, Section 4.1.1)
struct DnsHeader
{
  uint16_t id = 0;
  bool qr = false; // 0 = query, 1 = response
  DnsOpCode opcode = DnsOpCode::Query;
  bool aa = false; // authoritative answer
  bool tc = false; // truncated
  bool rd = true;  // recursion desired
  bool ra = false; // recursion available
  DnsRCode rcode = DnsRCode::NoError;
  uint16_t qdcount = 0; // question count
  uint16_t ancount = 0; // answer count
  uint16_t nscount = 0; // authority count
  uint16_t arcount = 0; // additional count
};

// DNS question entry (RFC 1035, Section 4.1.2)
struct DnsQuestion
{
  std::string name;
  DnsType type = DnsType::A;
  DnsClass cls = DnsClass::IN;
};

// DNS resource record (RFC 1035, Section 4.1.3)
struct DnsRecord
{
  std::string name;
  DnsType type = DnsType::A;
  DnsClass cls = DnsClass::IN;
  uint32_t ttl = 0;
  std::vector<uint8_t> rdata;

  // Convenience accessors for common record types
  std::string rdataAsIPv4() const;
  std::string rdataAsIPv6() const;
  std::string rdataAsName() const;
};

// Complete DNS message
struct DnsMessage
{
  DnsHeader header;
  std::vector<DnsQuestion> questions;
  std::vector<DnsRecord> answers;
  std::vector<DnsRecord> authority;
  std::vector<DnsRecord> additional;

  // Build a standard A-record query
  static DnsMessage query(const std::string &name, DnsType type = DnsType::A, uint16_t id = 0);
};

} // namespace Netpp::Dns
