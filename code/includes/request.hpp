#pragma once
#include "./header.hpp"

class Request
{
public:
    std::string method;
    std::string url;
    std::map<std::string, std::string> headers;
    std::string body;
    bool is_api;

    Request(const std::string buffer);
    ~Request();
};

std::ostream &operator<<(std::ostream &os, const Request &req);