#pragma once

#include <chrono>
#include <filesystem>
#include <fstream>

#include "Netpp/Connection.h"
#include "Netpp/FileStream.h"
#include "Netpp/Http/HttpRequest.h"
#include "Netpp/Http/HttpResponse.h"
#include "Netpp/Logger/Logger.h"

namespace Netpp::Http
{

using Logger::logger;
using Logger::LogLevel;

class HttpFileServer
{
public:
  HttpFileServer(std::filesystem::path root, bool enableDir, std::string index = "index.html")
      : _root(std::move(root)), _enableDir(enableDir), _index(std::move(index))
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

    res.status = 404;
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

    res.headers["content-length"] = std::to_string(size);
    res.headers["content-type"] = "text/plain";

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
      for (const auto &entry : std::filesystem::directory_iterator(dirname))
      {
        if (entry.is_regular_file() || entry.is_directory())
        {
          auto size = entry.is_regular_file() ? entry.file_size() : 0;
          auto lastWrite = entry.last_write_time();

          // time to string
          auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
              lastWrite - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now());
          auto tt = std::chrono::system_clock::to_time_t(sctp);

          std::string timeStr(std::ctime(&tt));
          timeStr.pop_back(); // Remove newline

          ss << "<tr><td><a href=\"/src/" << entry.path().filename().string() << "\">"
             << entry.path().filename().string() << "</a></td>"
             << "<td class=\"right\">" << size << " B</td>"
             << "<td class=\"right\">" << timeStr << "</td></tr>\n";
        }
      }
    }
    catch (const std::exception &e)
    {
      logger("fsrv", LogLevel::ERROR, e.what());
      res.status = 500;
      return;
    }

    ss << "</tbody>\n</table>\n</body>\n</html>\n";
    res.setBody(ss.str());
  }

  std::filesystem::path _root;
  bool _enableDir;
  std::string _index;
};

} // namespace Netpp::Http