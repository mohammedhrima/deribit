#pragma once
#include "./header.hpp"

class Server
{
private:
    int fd;
    size_t port;

public:
    Server(int port_);
    void init();
    void sendResponse(int client_fd, int statusCode, const std::string &body, std::string content_type);
    void serve_static_file(int client_fd, Request &req);
    void start(Api &api);
    ~Server();
};