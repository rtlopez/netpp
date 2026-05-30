#pragma once

#include <fstream>
#include <string>

#include "DataEvent.h"

namespace Netpp
{

class FileStream
{
public:
  FileStream(ConnectionPtr conn, const std::string &filename)
      : _conn(conn), _file(filename, std::ios::binary | std::ios::in)
  {
  }

  FileStream(const FileStream &) = delete;
  FileStream &operator=(const FileStream &) = delete;
  FileStream(FileStream &&) = default;
  FileStream &operator=(FileStream &&) = default;

  DataEvent operator()()
  {
    std::string line;
    std::getline(_file, line);
    line += "\n";
    return {.conn = _conn, .buffer = {line.begin(), line.end()}, .close = _file.eof()};
  }

private:
  ConnectionPtr _conn;
  std::ifstream _file;
};

} // namespace Netpp