#pragma once

#include <fstream>
#include <string>

#include "DataEvent.h"

namespace Netpp
{

class FileStream
{
public:
  FileStream(ConnectionPtr conn, const std::string &filename, size_t size = 2048)
      : _conn(conn), _file(filename, std::ios::binary | std::ios::in), _size(size)
  {
  }

  FileStream(const FileStream &) = delete;
  FileStream &operator=(const FileStream &) = delete;
  FileStream(FileStream &&) = default;
  FileStream &operator=(FileStream &&) = default;

  DataEvent operator()()
  {
    if (!_size)
    {
      std::string line;
      std::getline(_file, line);
      line += "\n";
      debug("STREAM", line.size(), _file.eof());
      return {.conn = _conn, .buffer = {line.begin(), line.end()}, .close = _file.eof()};
    }
    else
    {
      std::vector<uint8_t> buffer(_size);
      _file.read(reinterpret_cast<char *>(buffer.data()), _size);
      auto bytesRead = _file.gcount();
      buffer.resize(static_cast<size_t>(bytesRead));
      debug("STREAM", buffer.size(), _file.eof());
      return {.conn = _conn, .buffer = std::move(buffer), .close = _file.eof()};
    }
  }

private:
  ConnectionPtr _conn;
  std::ifstream _file;
  size_t _size;
};

} // namespace Netpp