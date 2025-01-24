#include "./includes/header.hpp"

Api::Api(std::string _path, std::string _url, size_t _port) : url(_url), path(_path), port(_port) {};

Api::~Api()
{
    SSL_CTX_free(ctx);
    EVP_cleanup();
    SSL_shutdown(ssl);
    SSL_free(ssl);
};

void Api::init()
{
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        throw Error("failed to created socket");

    timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)))
        throw Error("failed to set socket options");

    hostent *host = gethostbyname(url.c_str());
    if (!host)
        throw Error("failed to resolve host");

    sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    memcpy(&server_address.sin_addr, host->h_addr_list[0], host->h_length);

    if (::connect(fd, (struct sockaddr *)&server_address, sizeof(server_address)) < 0)
        throw Error("Connection failed");

    // init ssl
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD *method = TLS_client_method();
    ctx = SSL_CTX_new(method);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_verify_depth(ctx, 4);
    SSL_CTX_load_verify_locations(ctx, nullptr, "/etc/ssl/certs");

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, url.c_str());

    if (SSL_connect(ssl) <= 0)
        throw Error("SSL handshake failed");
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert)
        throw Error("Invalid certificate");
    X509_free(cert);
};

void Api::handshake()
{
    std::cout << GREEN << "Make the handshake " << RESET << std::endl;
    std::ostringstream request;
    request << "GET " << path << " HTTP/1.1\r\n"
            << "Host: " << url << "\r\n"
            << "Upgrade: websocket\r\n"
            << "Connection: Upgrade\r\n"
            << "Sec-WebSocket-Key: " << Random::key() << "\r\n"
            << "Sec-WebSocket-Version: 13\r\n\r\n";
    if (SSL_write(ssl, request.str().c_str(), request.str().size()) <= 0)
        throw Error("Failed to send WebSocket handshake");

    char response[BUFFERSIZE + 1] = {0};
    if (SSL_read(ssl, response, BUFFERSIZE) < 0)
        throw Error("Failed to read handshake response");

    if (std::string(response).find("101 Switching Protocols") == std::string::npos)
        throw Error("WebSocket upgrade failed");
    std::cout << GREEN << "Handshake response:\n"
              << RESET << response << std::endl;
};

// api handlers
std::vector<uint8_t> Api::mask_data(const std::string &message)
{
    std::vector<uint8_t> masked;
    std::random_device rd;
    uint8_t mask[4];
    for (int i = 0; i < 4; ++i)
        mask[i] = rd() & 0xFF;
    masked.reserve(message.size() + 4);
    masked.insert(masked.end(), mask, mask + 4);
    for (size_t i = 0; i < message.size(); ++i)
        masked.push_back(message[i] ^ mask[i % 4]);
    return masked;
}

int Api::sendMessage(std::string message)
{
    std::vector<uint8_t> frame;
    frame.push_back(0x81);

    auto masked_payload = mask_data(message);
    if (message.size() <= 125)
        frame.push_back(0x80 | message.size());
    else if (message.size() <= 65535)
    {
        frame.push_back(0x80 | 126);
        frame.push_back((message.size() >> 8) & 0xFF);
        frame.push_back(message.size() & 0xFF);
    }
    else
    {
        frame.push_back(0x80 | 127);
        for (int i = 7; i >= 0; --i)
            frame.push_back((message.size() >> (i * 8)) & 0xFF);
    }
    frame.insert(frame.end(), masked_payload.begin(), masked_payload.end());
    return SSL_write(ssl, frame.data(), frame.size()) > 0;
}

int Api::receiveMessage(std::string &message)
{
    uint8_t header[2];
    int bytes;
    if ((bytes = SSL_read(ssl, header, 2)) <= 0)
        return bytes;
    if (!(header[0] & 0x80))
    {
        std::cerr << RED << "Fragmented messages not supported" << RESET << std::endl;
        return -1;
    }

    uint64_t payload_length = header[1] & 0x7F;

    if (payload_length == 126)
    {
        uint8_t length_bytes[2];
        SSL_read(ssl, length_bytes, 2);
        payload_length = (length_bytes[0] << 8) | length_bytes[1];
    }
    else if (payload_length == 127)
    {
        uint8_t length_bytes[8];
        SSL_read(ssl, length_bytes, 8);
        payload_length = 0;
        for (int i = 0; i < 8; ++i)
        {
            payload_length = (payload_length << 8) | length_bytes[i];
        }
    }

    std::vector<uint8_t> payload(payload_length);
    if ((bytes = SSL_read(ssl, payload.data(), payload_length)) <= 0)
        return bytes;

    message = std::string(payload.begin(), payload.end());
    return bytes > 0;
}

bool Api::isError(const std::string &response)
{
    try
    {
        json j = json::parse(response);
        for (auto &element : j.items())
        {
            if (element.key() == "error")
            {
                std::cout << RED << "Error: " << RESET << element.value() << std::endl;
                return true;
            }
        }
    }
    catch (const json::parse_error &e)
    {
        std::cerr << "Error parsing JSON: " << e.what() << std::endl;
    }
    return false;
}

bool Api::authenticate(std::string client_id, std::string client_secret)
{
    std::cout << GREEN << "Authenticate " << RESET << std::endl;

    std::ostringstream message;
    message << R"({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "public/auth",
        "params": {
            "grant_type": "client_credentials",
            "client_id": ")"
            << client_id << R"(",
            "client_secret": ")"
            << client_secret << R"("
        }
    })";

    if (!sendMessage(message.str()))
        throw Error("authenticate: failed to sendMessage to api");

    std::string response;
    if (receiveMessage(response))
    {
        if (isError(response))
            std::cout << RED << "Failed to authenticate" << RESET << std::endl;
        else
        {
            std::cout << GREEN << "Authenticated succefully " << RESET << std::endl;
            return true;
        }
    }
    return false;
}

bool Api::place_order(const std::string &instrument, double amount, double price, const std::string type = "limit")
{
    std::ostringstream message;
    message << R"({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "private/buy",
        "params": {
            "instrument_name": ")"
            << instrument << R"(",
            "amount": )"
            << amount << R"(, "type": ")" << type << R"(", "price": )" << price << R"( 
            }
    })";

    if (!sendMessage(message.str()))
        throw Error("place_order: failed to sendMessage to api");

    std::string response;
    if (receiveMessage(response))
    {
        if (isError(response))
            std::cout << RED << "Failed to place order" << RESET << std::endl;
        else
        {
            std::cout << GREEN << "Order placed succefully " << RESET << std::endl;
            std::cout << response << std::endl;
            return true;
        }
    }
    return false;
}

bool Api::modify_order(const std::string &order_id, double amount, double price)
{
    std::ostringstream message;
    message << R"({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "private/edit",
        "params": {
            "order_id": ")"
            << order_id << R"(",
            "amount": )"
            << amount << R"(,
            "price": )"
            << price << R"(
        }
    })";

    if (!sendMessage(message.str()))
        throw Error("modify_order: failed to sendMessage to api");

    std::string response;
    if (receiveMessage(response))
    {
        if (isError(response))
            std::cout << RED << "Failed to modify order" << RESET << std::endl;
        else
        {
            std::cout << GREEN << "Order modified succefully " << RESET << std::endl;
            std::cout << response << std::endl;
            return true;
        }
    }
    return false;
}

bool Api::cancel_order(const std::string &order_id)
{
    std::ostringstream message;
    message << R"({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "private/cancel",
        "params": {
            "order_id": ")"
            << order_id << R"("
        }
    })";

    if (!sendMessage(message.str()))
        throw Error("cancel_order: failed to sendMessage to api");

    std::string response;
    if (receiveMessage(response))
    {
        if (isError(response))
            std::cout << RED << "Failed to modify order" << RESET << std::endl;
        else
        {
            std::cout << GREEN << "Order canceled succefully " << RESET << std::endl;
            std::cout << response << std::endl;
            return true;
        }
    }
    return false;
}

bool Api::get_order_book(const std::string &instrument_name, int depth, std::string &response)
{
    std::ostringstream message;
    message << R"({
        "jsonrpc": "2.0",
        "id": 42,
        "method": "public/get_order_book",
        "params": {
            "instrument_name": ")"
            << instrument_name << R"(",
            "depth": )"
            << depth << R"(
            }
        })";

    if (!sendMessage(message.str()))
        throw Error("Failed to request order book");

    if (receiveMessage(response))
    {
        if (isError(response))
            std::cout << RED << "Failed to get order book" << RESET << std::endl;
        else
        {
            std::cout << GREEN << "get order book succefully " << RESET << std::endl;
            std::cout << response << std::endl;
            return true;
        }
    }
    return false;
}

bool Api::get_positions(const std::string &currency, std::string &response)
{
    std::ostringstream message;
    message << R"({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "private/get_positions",
            "params": {
                "currency": ")"
            << currency << R"("
            }
        })";

    if (!sendMessage(message.str()))
        throw Error("Failed to request positions");

    if (receiveMessage(response))
    {
        if (isError(response))
            std::cout << RED << "Failed to get positions" << RESET << std::endl;
        else
        {
            std::cout << GREEN << "get positions successfully" << RESET << std::endl;
            std::cout << response << std::endl;
            return true;
        }
    }
    return false;
}