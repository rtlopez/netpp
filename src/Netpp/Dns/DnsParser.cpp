#include "Netpp/Dns/DnsParser.h"

#include <arpa/inet.h>

namespace Netpp::Dns
{

// ── Serialization ──────────────────────────────────────────────────────

std::vector<uint8_t> DnsParser::serialize(const DnsMessage &msg)
{
  std::vector<uint8_t> buf;
  buf.reserve(512);

  writeHeader(buf, msg.header);

  for (const auto &q : msg.questions)
  {
    writeQuestion(buf, q);
  }
  for (const auto &r : msg.answers)
  {
    writeRecord(buf, r);
  }
  for (const auto &r : msg.authority)
  {
    writeRecord(buf, r);
  }
  for (const auto &r : msg.additional)
  {
    writeRecord(buf, r);
  }

  return buf;
}

void DnsParser::writeU16(std::vector<uint8_t> &buf, uint16_t val)
{
  buf.push_back(static_cast<uint8_t>(val >> 8));
  buf.push_back(static_cast<uint8_t>(val & 0xFF));
}

void DnsParser::writeU32(std::vector<uint8_t> &buf, uint32_t val)
{
  buf.push_back(static_cast<uint8_t>((val >> 24) & 0xFF));
  buf.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
  buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
  buf.push_back(static_cast<uint8_t>(val & 0xFF));
}

void DnsParser::writeName(std::vector<uint8_t> &buf, const std::string &name)
{
  size_t pos = 0;
  while (pos < name.size())
  {
    size_t dot = name.find('.', pos);
    if (dot == std::string::npos)
    {
      dot = name.size();
    }

    size_t labelLen = dot - pos;
    if (labelLen == 0)
    {
      pos = dot + 1;
      continue;
    }
    if (labelLen > 63)
    {
      throw DnsParseError("label exceeds 63 characters");
    }

    buf.push_back(static_cast<uint8_t>(labelLen));
    buf.insert(buf.end(), name.begin() + static_cast<long>(pos), name.begin() + static_cast<long>(dot));
    pos = dot + 1;
  }
  buf.push_back(0); // root label
}

void DnsParser::writeHeader(std::vector<uint8_t> &buf, const DnsHeader &hdr)
{
  writeU16(buf, hdr.id);

  uint16_t flags = 0;
  if (hdr.qr)
  {
    flags |= (1 << 15);
  }
  flags |= (static_cast<uint16_t>(hdr.opcode) & 0x0F) << 11;
  if (hdr.aa)
  {
    flags |= (1 << 10);
  }
  if (hdr.tc)
  {
    flags |= (1 << 9);
  }
  if (hdr.rd)
  {
    flags |= (1 << 8);
  }
  if (hdr.ra)
  {
    flags |= (1 << 7);
  }
  flags |= static_cast<uint16_t>(hdr.rcode) & 0x0F;

  writeU16(buf, flags);
  writeU16(buf, hdr.qdcount);
  writeU16(buf, hdr.ancount);
  writeU16(buf, hdr.nscount);
  writeU16(buf, hdr.arcount);
}

void DnsParser::writeQuestion(std::vector<uint8_t> &buf, const DnsQuestion &q)
{
  writeName(buf, q.name);
  writeU16(buf, static_cast<uint16_t>(q.type));
  writeU16(buf, static_cast<uint16_t>(q.cls));
}

void DnsParser::writeRecord(std::vector<uint8_t> &buf, const DnsRecord &r)
{
  writeName(buf, r.name);
  writeU16(buf, static_cast<uint16_t>(r.type));
  writeU16(buf, static_cast<uint16_t>(r.cls));
  writeU32(buf, r.ttl);
  writeU16(buf, static_cast<uint16_t>(r.rdata.size()));
  buf.insert(buf.end(), r.rdata.begin(), r.rdata.end());
}

// ── Parsing ────────────────────────────────────────────────────────────

void DnsParser::Reader::ensureAvailable(size_t n) const
{
  if (pos + n > len)
  {
    throw DnsParseError("unexpected end of packet");
  }
}

uint8_t DnsParser::Reader::readU8()
{
  ensureAvailable(1);
  return data[pos++];
}

uint16_t DnsParser::Reader::readU16()
{
  ensureAvailable(2);
  uint16_t val = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
  pos += 2;
  return val;
}

uint32_t DnsParser::Reader::readU32()
{
  ensureAvailable(4);
  uint32_t val = (static_cast<uint32_t>(data[pos]) << 24) | (static_cast<uint32_t>(data[pos + 1]) << 16) |
                 (static_cast<uint32_t>(data[pos + 2]) << 8) | data[pos + 3];
  pos += 4;
  return val;
}

void DnsParser::Reader::skip(size_t n)
{
  ensureAvailable(n);
  pos += n;
}

DnsMessage DnsParser::parse(const uint8_t *data, size_t len)
{
  if (len < 12)
  {
    throw DnsParseError("packet too short for DNS header");
  }

  Reader reader{data, len, 0};
  DnsMessage msg;

  msg.header = readHeader(reader);

  for (uint16_t i = 0; i < msg.header.qdcount; i++)
  {
    msg.questions.push_back(readQuestion(reader));
  }
  for (uint16_t i = 0; i < msg.header.ancount; i++)
  {
    msg.answers.push_back(readRecord(reader));
  }
  for (uint16_t i = 0; i < msg.header.nscount; i++)
  {
    msg.authority.push_back(readRecord(reader));
  }
  for (uint16_t i = 0; i < msg.header.arcount; i++)
  {
    msg.additional.push_back(readRecord(reader));
  }

  return msg;
}

DnsHeader DnsParser::readHeader(Reader &reader)
{
  DnsHeader hdr;
  hdr.id = reader.readU16();

  uint16_t flags = reader.readU16();
  hdr.qr = (flags >> 15) & 1;
  hdr.opcode = static_cast<DnsOpCode>((flags >> 11) & 0x0F);
  hdr.aa = (flags >> 10) & 1;
  hdr.tc = (flags >> 9) & 1;
  hdr.rd = (flags >> 8) & 1;
  hdr.ra = (flags >> 7) & 1;
  hdr.rcode = static_cast<DnsRCode>(flags & 0x0F);

  hdr.qdcount = reader.readU16();
  hdr.ancount = reader.readU16();
  hdr.nscount = reader.readU16();
  hdr.arcount = reader.readU16();

  return hdr;
}

/// Reads a DNS name starting at reader.pos, advancing past it.
/// Follows compression pointers (RFC 1035, Section 4.1.4) for the name
/// content, but only advances reader.pos past the bytes consumed in the
/// original stream (labels + final null, or labels + 2-byte pointer).
std::string DnsParser::readName(Reader &reader)
{
  std::string name;
  bool jumped = false;
  size_t jumpReturnPos = 0;

  while (reader.pos < reader.len)
  {
    uint8_t labelLen = reader.data[reader.pos];

    if (labelLen == 0)
    {
      reader.pos++;
      break;
    }

    // Pointer compression: top two bits = 11
    if ((labelLen & 0xC0) == 0xC0)
    {
      reader.ensureAvailable(2);
      uint16_t pointer = ((static_cast<uint16_t>(labelLen) & 0x3F) << 8) | reader.data[reader.pos + 1];
      if (!jumped)
      {
        jumpReturnPos = reader.pos + 2;
      }
      jumped = true;
      reader.pos = pointer;
      continue;
    }

    reader.ensureAvailable(1 + labelLen);
    if (!name.empty())
    {
      name += '.';
    }
    name.append(reinterpret_cast<const char *>(reader.data + reader.pos + 1), labelLen);
    reader.pos += 1 + labelLen;
  }

  if (jumped)
  {
    reader.pos = jumpReturnPos;
  }

  return name;
}

std::string DnsParser::readNameAt(const uint8_t *data, size_t len, size_t offset, int depth)
{
  if (depth > 16)
  {
    throw DnsParseError("name compression loop detected");
  }

  Reader reader{data, len, offset};
  std::string name;

  while (reader.pos < reader.len)
  {
    uint8_t labelLen = reader.data[reader.pos];

    if (labelLen == 0)
    {
      break;
    }

    if ((labelLen & 0xC0) == 0xC0)
    {
      reader.ensureAvailable(2);
      uint16_t pointer = ((static_cast<uint16_t>(labelLen) & 0x3F) << 8) | reader.data[reader.pos + 1];
      auto suffix = readNameAt(data, len, pointer, depth + 1);
      if (!name.empty())
      {
        name += '.';
      }
      name += suffix;
      break;
    }

    reader.ensureAvailable(1 + labelLen);
    if (!name.empty())
    {
      name += '.';
    }
    name.append(reinterpret_cast<const char *>(reader.data + reader.pos + 1), labelLen);
    reader.pos += 1 + labelLen;
  }

  return name;
}

DnsQuestion DnsParser::readQuestion(Reader &reader)
{
  DnsQuestion q;
  q.name = readName(reader);
  q.type = static_cast<DnsType>(reader.readU16());
  q.cls = static_cast<DnsClass>(reader.readU16());
  return q;
}

DnsRecord DnsParser::readRecord(Reader &reader)
{
  DnsRecord r;
  r.name = readName(reader);
  r.type = static_cast<DnsType>(reader.readU16());
  r.cls = static_cast<DnsClass>(reader.readU16());
  r.ttl = reader.readU32();
  uint16_t rdlen = reader.readU16();
  reader.ensureAvailable(rdlen);
  r.rdata.assign(reader.data + reader.pos, reader.data + reader.pos + rdlen);
  reader.pos += rdlen;
  return r;
}

// ── DnsRecord convenience accessors ────────────────────────────────────

std::string DnsRecord::rdataAsIPv4() const
{
  if (rdata.size() != 4)
  {
    return {};
  }
  char buf[INET_ADDRSTRLEN];
  ::inet_ntop(AF_INET, rdata.data(), buf, sizeof(buf));
  return buf;
}

std::string DnsRecord::rdataAsIPv6() const
{
  if (rdata.size() != 16)
  {
    return {};
  }
  char buf[INET6_ADDRSTRLEN];
  ::inet_ntop(AF_INET6, rdata.data(), buf, sizeof(buf));
  return buf;
}

std::string DnsRecord::rdataAsName() const
{
  if (rdata.empty())
  {
    return {};
  }
  std::string name;
  size_t pos = 0;
  while (pos < rdata.size())
  {
    uint8_t labelLen = rdata[pos];
    if (labelLen == 0)
    {
      break;
    }
    if ((labelLen & 0xC0) == 0xC0)
    {
      break; // can't resolve pointers without full packet context
    }
    if (pos + 1 + labelLen > rdata.size())
    {
      break;
    }
    if (!name.empty())
    {
      name += '.';
    }
    name.append(reinterpret_cast<const char *>(rdata.data() + pos + 1), labelLen);
    pos += 1 + labelLen;
  }
  return name;
}

// ── DnsMessage factory ─────────────────────────────────────────────────

DnsMessage DnsMessage::query(const std::string &name, DnsType type, uint16_t id)
{
  DnsMessage msg;
  msg.header.id = id;
  msg.header.rd = true;
  msg.header.qdcount = 1;
  msg.questions.push_back({name, type, DnsClass::IN});
  return msg;
}

} // namespace Netpp::Dns
