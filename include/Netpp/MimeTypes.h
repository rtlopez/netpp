#pragma once

#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>

namespace Netpp
{
class MimeTypes
{
public:
  MimeTypes(std::filesystem::path mimetTypeSourceFile)
  {
    std::ifstream file(mimetTypeSourceFile);
    if (!file)
    {
      throw std::runtime_error("Failed to open mime types source file: " + mimetTypeSourceFile.string());
    }

    std::string line;
    while (std::getline(file, line))
    {
      // Skip comments and empty lines
      if (line.empty() || line[0] == '#')
      {
        continue;
      }

      std::istringstream iss(line);
      std::string mimeType;
      iss >> mimeType;

      std::string extension;
      while (iss >> extension)
      {
        mimeTypes[extension] = mimeType;
      }
    }
  }

  std::optional<std::string> getMimeType(const std::string &extension) const
  {
    auto it = mimeTypes.find(extension);
    if (it != mimeTypes.end())
    {
      return it->second;
    }
    return std::nullopt;
  }

private:
  std::unordered_map<std::string, std::string> mimeTypes;
};
} // namespace Netpp