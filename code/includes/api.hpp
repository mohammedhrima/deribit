#pragma once
#include "./header.hpp"

class Api
{
private:
    int fd;
    SSL *ssl;
    SSL_CTX *ctx;
    std::string url;
    std::string path;
    size_t port;

public:
    Api(std::string _path, std::string _url, size_t _port);
    ~Api();

    void init();
    void handshake();
    std::vector<uint8_t> mask_data(const std::string &message);
    int sendMessage(std::string message);
    int receiveMessage(std::string &message);
    bool isError(const std::string &response);
    bool authenticate(std::string client_id, std::string client_secret);
    bool place_order(const std::string &instrument, double amount, double price, const std::string type);
    bool modify_order(const std::string &order_id, double amount, double price);
    bool cancel_order(const std::string &order_id);
    bool get_order_book(const std::string &instrument_name, int depth, std::string &response);
    bool get_positions(const std::string &currency, std::string &response);
};
