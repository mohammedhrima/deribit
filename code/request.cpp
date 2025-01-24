#include "./includes/header.hpp"

Request::Request(const std::string buffer)
{
    std::istringstream stream(buffer);
    std::string line;

    std::getline(stream, line);
    std::istringstream reqline(line);
    reqline >> method >> url;

    while (std::getline(stream, line) && line != "\r")
    {
        size_t pos = line.find(":");
        if (pos != std::string::npos)
        {
            std::string key = trim(line.substr(0, pos));
            std::string value = trim(line.substr(pos + 2));
            headers[key] = value;
        }
    }

    is_api = starts_with(url, "/api/");

    while (std::getline(stream, line))
        body += line + "\n";
};

Request::~Request() {};

std::ostream &operator<<(std::ostream &os, const Request &req)
{
    os << "method: " << req.method << "\n";
    os << "url: " << req.url << "\n";
    os << "headers:\n";
    for (const auto &header : req.headers)
        os << "  " << header.first << ": " << header.second << "\n";
    os << "body: " << req.body << "\n";
    return os;
}
