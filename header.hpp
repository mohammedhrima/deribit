#pragma once

#include <iostream>
#include <string>
#include <sstream>
#include <thread>
#include <vector>
#include <random>
#include <cstring>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#define PORT 5000
#define MAX_CONNECTIONS 10
#define BUFFER_SIZE 4096
#define CRLF "\r\n"

#define CLIENT_ID "6ljNdSET"
#define CLIENT_SECRET "R08jkZ_yC7yzHfrl1o0MXxIlSZwmJ-AaboLOJqcNCgM"

typedef struct sockaddr_in sockaddr_in;

// Base64 class definition (add this)
class Base64 {
private:
    static const std::string base64_chars;
public:
    static std::string encode(const unsigned char* bytes_to_encode, size_t in_len);
};

// WebSocket Client class definition (add this)
class WebSocketClient {
private:
    SSL_CTX* ctx;
    SSL* ssl;
    int sock;
    std::string server_url;
    int server_port;
    std::string path;
    bool is_authenticated;

    std::string generateWebSocketKey();
    std::vector<uint8_t> maskData(const std::string& payload);
    std::vector<uint8_t> createFrame(const std::string& payload);

public:
    WebSocketClient(const std::string& url, int port, const std::string& ws_path);
    ~WebSocketClient();

    bool connect();
    void disconnect();
    bool send(const std::string& message);
    bool receive(std::string& message);
    bool authenticate(const std::string& client_id, const std::string& client_secret);
    bool isAuthenticated() const { return is_authenticated; }
};

class Server {
public:
    Server() {}
    ~Server() {}
};

class Client {
public:
    Client() {}
    ~Client() {}
};

class Error : public std::exception {
private:
    std::string error_message;
public:
    Error(const std::string& message) : error_message(message) {}
    const char* what() const noexcept override {
        return error_message.c_str();
    }
};

enum Status {
    HTTP_NONE = 0,
    HTTP_OK = 200,
    HTTP_CREATED = 201,
    HTTP_NO_CONTENT = 204,
    HTTP_MOVE_PERMANENTLY = 301,
    HTTP_TEMPORARY_REDIRECT = 307,
    HTTP_PERMANENT_REDIRECT = 308,
    HTTP_BAD_REQUEST = 400,
    HTTP_FORBIDEN = 403,
    HTTP_NOT_FOUND = 404,
    HTTP_METHOD_NOT_ALLOWED = 405,
    HTTP_TIMEOUT = 408,
    HTTP_LENGTH_REQUIRED = 411,
    HTTP_CONTENT_TO_LARGE = 413,
    HTTP_URI_TO_LARGE = 414,
    HTTP_HEADER_TO_LARGE = 431,
    HTTP_INTERNAL_SERVER = 500,
    HTTP_NOT_IMPLEMENTED = 501,
    HTTP_BAD_GATEWAY = 502,
    HTTP_GATEWAY_TIMEOUT = 504,
    HTTP_INSUPPORTED_HTTP = 505,
};