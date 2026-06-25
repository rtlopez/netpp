#pragma once

#include <chrono>
#include <filesystem>
#include <fstream>

#include "Netpp/Connection.h"
#include "Netpp/FileStream.h"
#include "Netpp/Http/HttpRequest.h"
#include "Netpp/Http/HttpResponse.h"
#include "Netpp/Logger/Logger.h"
#include "Netpp/MimeTypes.h"

namespace Netpp::Http
{

using Logger::logger;
using Logger::LogLevel;

class HttpFileServer
{
public:
  HttpFileServer(std::filesystem::path root, bool enableDir, std::string index, Netpp::MimeTypes &mimeTypes)
      : _root(std::move(root)), _enableDir(enableDir), _index(std::move(index)), _mimeTypes(mimeTypes)
  {
  }
  ~HttpFileServer() = default;

  void operator()(HttpRequest &req, HttpResponse &res, ConnectionPtr)
  {
    auto filename = _root / std::filesystem::path(req.path.substr(1));
    auto isFile = std::filesystem::is_regular_file(filename);
    auto isDir = std::filesystem::is_directory(filename);
    logger("fsrv", LogLevel::INFO, _root, filename, isFile, isDir);

    if (isFile)
    {
      serveFile(res, filename);
      return;
    }

    if (_enableDir && isDir)
    {
      auto index = filename / _index;
      if (std::filesystem::is_regular_file(index))
      {
        serveFile(res, index);
        return;
      }
      serveDirectory(res, filename);
      return;
    }

    res.status = 403;
  }

private:
  void serveFile(HttpResponse &res, const std::filesystem::path &filename)
  {
    std::ifstream file(filename, std::ios::binary | std::ios::in);
    if (!file)
    {
      res.status = 500;
      return;
    }
    auto size = std::filesystem::file_size(filename);
    auto extension = filename.extension().string();
    auto mimeType = _mimeTypes.getMimeType(extension);

    res.headers["content-length"] = std::to_string(size);
    res.headers["content-type"] = mimeType.value_or("text/plain");

    auto stream = std::make_unique<FileStream>(filename.string(), std::move(file));
    res.setGenerator([stream = std::move(stream)]() { return (*stream)(); });
  }

  void serveDirectory(HttpResponse &res, const std::filesystem::path &dirname)
  {
    std::ostringstream ss;
    ss << "<html>\n<head>\n<title>src/ Directory</title>\n<style>\n"
       << "body { font-family: monospace; margin: 20px; }\n"
       << "table { border-collapse: collapse; width: 100%; }\n"
       << "th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }\n"
       << "th.right, td.right { border: 1px solid #ccc; padding: 8px; text-align: right; }\n"
       << "th { background-color: #f0f0f0; }\n"
       << "</style>\n</head>\n<body>\n"
       << "<h1>Directory: src/</h1>\n"
       << "<table>\n<thead>\n<tr><th>File</th><th class=\"right\">Size</th><th "
          "class=\"right\">Modified</th></tr>\n</thead>\n<tbody>\n";

    try
    {
      std::vector<std::filesystem::directory_entry> entries;

      // Count entries first to preallocate vector memory
      size_t entryCount = 0;
      for (const auto &entry : std::filesystem::directory_iterator(dirname))
      {
        if (entry.is_regular_file() || entry.is_directory())
        {
          entryCount++;
        }
      }
      entries.reserve(entryCount);

      for (const auto &entry : std::filesystem::directory_iterator(dirname))
      {
        if (entry.is_regular_file() || entry.is_directory())
        {
          entries.push_back(entry);
        }
      }

      std::sort(entries.begin(), entries.end(), [](const auto &a, const auto &b) {
        if (a.is_directory() != b.is_directory())
        {
          return a.is_directory() > b.is_directory();
        }
        return a.path().filename().string() < b.path().filename().string();
      });

      for (const auto &entry : entries)
      {
        auto name = entry.path().filename().string();
        auto relativePath = std::filesystem::relative(entry.path(), _root);

        ss << "<tr><td>"
           << "<a href=\"/" << escapeHtml(escapeUrlPath(relativePath.string())) << "\">" << escapeHtml(name)
           << "</a></td>"
           << "<td class=\"right\">" << escapeHtml(makeSizeOrDirString(entry)) << "</td>"
           << "<td class=\"right\">" << escapeHtml(makeLastModificationString(entry)) << "</td></tr>\n";
      }
    }
    catch (const std::exception &e)
    {
      logger("fsrv", LogLevel::ERROR, e.what());
      res.status = 500;
      return;
    }

    ss << "</tbody>\n</table>\n</body>\n</html>\n";
    res.setBody(std::move(ss).str());
  }

  std::string makeSizeOrDirString(const std::filesystem::directory_entry &entry)
  {
    if (entry.is_directory())
    {
      return "<DIR>";
    }
    else if (entry.is_regular_file())
    {
      return std::to_string(entry.file_size()) + " B";
    }
    else
    {
      return "?";
    }
  }

  std::string makeLastModificationString(const std::filesystem::directory_entry &entry)
  {
    auto lastWrite = entry.last_write_time();

    // time to string
    auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
        lastWrite - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now());
    auto tt = std::chrono::system_clock::to_time_t(sctp);

    auto *tm = std::ctime(&tt);
    if (!tm)
    {
      return "?";
    }

    std::string timeStr(tm);
    if (!timeStr.empty() && timeStr.back() == '\n')
    {
      timeStr.pop_back(); // Remove newline
    }

    return timeStr;
  }

  std::string escapeHtml(const std::string &str)
  {
    // calculate target size to avoid multiple reallocations
    size_t size = 0ul;
    for (char c : str)
    {
      switch (c)
      {
      case '&':
        size += 5; // &amp;
        break;
      case '<':
        size += 4; // &lt;
        break;
      case '>':
        size += 4; // &gt;
        break;
      case '"':
        size += 6; // &quot;
        break;
      case '\'':
        size += 5; // &#39;
        break;
      default:
        size += 1;
        break;
      }
    }
    // escape html special characters
    std::string escaped;
    escaped.reserve(size);
    for (char c : str)
    {
      switch (c)
      {
      case '&':
        escaped.append("&amp;");
        break;
      case '<':
        escaped.append("&lt;");
        break;
      case '>':
        escaped.append("&gt;");
        break;
      case '"':
        escaped.append("&quot;");
        break;
      case '\'':
        escaped.append("&#39;");
        break;
      default:
        escaped.push_back(c);
        break;
      }
    }
    return escaped;
  }

  std::string escapeUrlPath(const std::string &str)
  {
    std::ostringstream escaped;
    escaped << std::hex << std::uppercase;

    for (char c : str)
    {
      if (std::isalnum(static_cast<unsigned char>(c)) || c == '/' || c == '-' || c == '_' || c == '.' || c == '~')
      {
        escaped << c;
        continue;
      }

      escaped << '%' << std::setw(2) << std::setfill('0') << static_cast<int>(static_cast<unsigned char>(c));
    }

    return std::move(escaped).str();
  }

  std::filesystem::path _root;
  bool _enableDir;
  std::string _index;
  MimeTypes &_mimeTypes;
};

} // namespace Netpp::Http