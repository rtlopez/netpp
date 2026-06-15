#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include "Netpp/Dns/DnsMessage.h"

namespace Netpp::Dns
{

class DnsParseError : public std::runtime_error
{
public:
  explicit DnsParseError(const std::string &msg) : std::runtime_error("DNS parse error: " + msg)
  {
  }
};

/// Stateless DNS wire-format serializer/deserializer (RFC 1035).
///
/// Serialize:  DnsMessage -> std::vector<uint8_t>   (wire format)
/// Parse:      const uint8_t* + len -> DnsMessage
class DnsParser
{
public:
  /// Serialize a DnsMessage into wire-format bytes.
  static std::vector<uint8_t> serialize(const DnsMessage &msg);

  /// Parse a DNS wire-format packet into a DnsMessage.
  /// Throws DnsParseError on malformed input.
  static DnsMessage parse(const uint8_t *data, size_t len);

private:
  // -- Serialization helpers --

  static void writeU16(std::vector<uint8_t> &buf, uint16_t val);
  static void writeU32(std::vector<uint8_t> &buf, uint32_t val);

  /// Encode a domain name in DNS label format (e.g. "example.com" -> \x07example\x03com\x00)
  static void writeName(std::vector<uint8_t> &buf, const std::string &name);

  static void writeHeader(std::vector<uint8_t> &buf, const DnsHeader &hdr);
  static void writeQuestion(std::vector<uint8_t> &buf, const DnsQuestion &q);
  static void writeRecord(std::vector<uint8_t> &buf, const DnsRecord &r);

  // -- Parsing helpers --

  struct Reader
  {
    const uint8_t *data;
    size_t len;
    size_t pos = 0;

    uint8_t readU8();
    uint16_t readU16();
    uint32_t readU32();
    void skip(size_t n);
    void ensureAvailable(size_t n) const;
  };

  /// Decode a DNS domain name with pointer compression support (RFC 1035, Section 4.1.4)
  static std::string readName(Reader &reader);
  static std::string readTxt(Reader &reader);

  static DnsHeader readHeader(Reader &reader);
  static DnsQuestion readQuestion(Reader &reader);
  static DnsRecord readRecord(Reader &reader, bool withString = false);
};

} // namespace Netpp::Dns
