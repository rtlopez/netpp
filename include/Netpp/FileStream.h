#pragma once

#include <filesystem>
#include <fstream>
#include <string>

#include "Netpp/DataEvent.h"
#include "Netpp/Logger/Logger.h"

namespace Netpp
{

using Netpp::Logger::logger;
using Netpp::Logger::LogLevel;
static const char *FILESTREAM = "filestream";

class FileStream
{
public:
  FileStream(const std::filesystem::path &filename, size_t size = 2048)
      : _filename(filename), _file(filename, std::ios::binary | std::ios::in), _size(size)
  {
  }

  FileStream(const std::filesystem::path &filename, std::ifstream &&file, size_t size = 2048)
      : _filename(filename), _file(std::move(file)), _size(size)
  {
  }

  FileStream(const FileStream &) = delete;
  FileStream &operator=(const FileStream &) = delete;
  FileStream(FileStream &&) = default;
  FileStream &operator=(FileStream &&) = default;

  DataEvent operator()()
  {
    if (_size == 0)
    {
      std::string line;
      std::getline(_file, line);
      line += "\n";
      auto eventType = _file.eof() ? EventType::DONE : EventType::DATA;
      logger(FILESTREAM, LogLevel::DEBUG, line.size(), _file.eof(), (size_t)eventType);
      return {.buffer = {line.begin(), line.end()}, .eventType = eventType};
    }

    DataEvent::Buffer buffer(_size);
    _file.read(reinterpret_cast<char *>(buffer.data()), _size);
    auto bytesRead = _file.gcount();
    buffer.resize(static_cast<size_t>(bytesRead));
    auto eventType = _file.eof() ? EventType::DONE : EventType::DATA;
    logger(FILESTREAM, LogLevel::DEBUG, buffer.size(), _file.eof(), (size_t)eventType);
    return {.buffer = std::move(buffer), .eventType = eventType};
  }

private:
  std::filesystem::path _filename;
  std::ifstream _file;
  size_t _size;
};

} // namespace Netpp