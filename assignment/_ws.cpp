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
#include <nlohmann/json.hpp>

#define PORT 5000
#define MAX_CONNECTIONS 10

#define BUFFERSIZE 4096
#define CLIENT_ID "6ljNdSET"
#define CLIENT_SECRET "R08jkZ_yC7yzHfrl1o0MXxIlSZwmJ-AaboLOJqcNCgM"
#define DERIBIT_URL "test.deribit.com"
#define DERIBIT_PATH "/ws/api/v2"
#define DERIBIT_PORT 443

typedef struct timeval timeval;
typedef struct hostent hostent;
typedef struct sockaddr_in sockaddr_in;

class Error : public std::exception
{
private:
    std::string message;

public:
    Error(const char *msg) : message(msg) {};
    const char *what() const noexcept
    {
        return message.c_str();
    }
};

class Random
{
private:
    static constexpr char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static std::string base64Encode(const unsigned char *bytes_to_encode, size_t in_len)
    {
        std::string ret;
        int i = 0;
        int j = 0;
        unsigned char chars0[3];
        unsigned char chars1[4];
        while (in_len--)
        {
            chars0[i++] = *(bytes_to_encode++);
            if (i == 3)
            {
                chars1[0] = (chars0[0] & 0xfc) >> 2;
                chars1[1] = ((chars0[0] & 0x03) << 4) + ((chars0[1] & 0xf0) >> 4);
                chars1[2] = ((chars0[1] & 0x0f) << 2) + ((chars0[2] & 0xc0) >> 6);
                chars1[3] = chars0[2] & 0x3f;
                for (i = 0; i < 4; i++)
                    ret += base64_chars[chars1[i]];
                i = 0;
            }
        }
        if (i)
        {
            for (j = i; j < 3; j++)
                chars0[j] = '\0';
            chars1[0] = (chars0[0] & 0xfc) >> 2;
            chars1[1] = ((chars0[0] & 0x03) << 4) + ((chars0[1] & 0xf0) >> 4);
            chars1[2] = ((chars0[1] & 0x0f) << 2) + ((chars0[2] & 0xc0) >> 6);
            chars1[3] = chars0[2] & 0x3f;
            for (j = 0; j < i + 1; j++)
                ret += base64_chars[chars1[j]];
            while (i++ < 3)
                ret += '=';
        }
        return ret;
    }

public:
    static std::string key()
    {
        unsigned char random_bytes[16];
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);

        for (int i = 0; i < 16; ++i)
            random_bytes[i] = static_cast<unsigned char>(dis(gen));

        return base64Encode(random_bytes, sizeof(random_bytes));
    }
};

typedef struct Connection Connection;

struct Connection
{
    int fd;
    SSL *ssl;
    SSL_CTX *ctx;
    std::string url;
    std::string path;
};

void init_connection(Connection &con)
{
    con.fd = socket(AF_INET, SOCK_STREAM, 0);
    if (con.fd < 0)
        throw Error("failed to created socket");

    timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if (setsockopt(con.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)))
        throw Error("failed to set socket options");

    hostent *host = gethostbyname(con.url.c_str());
    if (!host)
        throw Error("failed to resolve host");

    sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(DERIBIT_PORT);
    memcpy(&server_address.sin_addr, host->h_addr_list[0], host->h_length);

    std::cout << "call ::connect" << std::endl;
    if (::connect(con.fd, (struct sockaddr *)&server_address, sizeof(server_address)) < 0)
        throw Error("Connection failed");

    // init ssl
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD *method = TLS_client_method();
    con.ctx = SSL_CTX_new(method);

    SSL_CTX_set_verify(con.ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_verify_depth(con.ctx, 4);
    SSL_CTX_load_verify_locations(con.ctx, nullptr, "/etc/ssl/certs");

    con.ssl = SSL_new(con.ctx);
    SSL_set_fd(con.ssl, con.fd);
    SSL_set_tlsext_host_name(con.ssl, con.url.c_str());

    if (SSL_connect(con.ssl) <= 0)
        throw Error("SSL handshake failed");
    X509 *cert = SSL_get_peer_certificate(con.ssl);
    if (!cert)
        throw Error("Invalid certificate");
    X509_free(cert);
}

void handshake(Connection &con)
{
    std::ostringstream request;
    request << "GET " << con.path << " HTTP/1.1\r\n"
            << "Host: " << con.url << "\r\n"
            << "Upgrade: websocket\r\n"
            << "Connection: Upgrade\r\n"
            << "Sec-WebSocket-Key: " << Random::key() << "\r\n"
            << "Sec-WebSocket-Version: 13\r\n\r\n";
    if (SSL_write(con.ssl, request.str().c_str(), request.str().size()) <= 0)
        throw Error("Failed to send WebSocket handshake");

    char response[BUFFERSIZE + 1] = {0};
    if (SSL_read(con.ssl, response, BUFFERSIZE) < 0)
        throw Error("Failed to read handshake response");

    if (std::string(response).find("101 Switching Protocols") == std::string::npos)
        throw Error("WebSocket upgrade failed");
}

void _connect(Connection &con)
{
    init_connection(con);
    std::cout << "before handshake" << std::endl;
    handshake(con);
    std::cout << "after handshake" << std::endl;
    std::cout << "connected succefully" << std::endl;
}

std::vector<uint8_t> mask_data(const std::string &message)
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

int sendMessage(Connection &con, std::string message)
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
    return SSL_write(con.ssl, frame.data(), frame.size()) > 0;
}

int receiveMessage(Connection &con, std::string &message)
{
    uint8_t header[2];
    int bytes;
    if ((bytes = SSL_read(con.ssl, header, 2)) <= 0)
        return bytes;
    if (!(header[0] & 0x80))
    {
        std::cerr << "Fragmented messages not supported" << std::endl;
        return -1;
    }

    uint8_t opcode = header[0] & 0x0F;
    uint8_t masked = header[1] & 0x80;
    uint64_t payload_length = header[1] & 0x7F;

    if (payload_length == 126)
    {
        uint8_t length_bytes[2];
        SSL_read(con.ssl, length_bytes, 2);
        payload_length = (length_bytes[0] << 8) | length_bytes[1];
    }
    else if (payload_length == 127)
    {
        uint8_t length_bytes[8];
        SSL_read(con.ssl, length_bytes, 8);
        payload_length = 0;
        for (int i = 0; i < 8; ++i)
        {
            payload_length = (payload_length << 8) | length_bytes[i];
        }
    }

    std::vector<uint8_t> payload(payload_length);
    if ((bytes = SSL_read(con.ssl, payload.data(), payload_length)) <= 0)
        return bytes;

    message = std::string(payload.begin(), payload.end());
    return bytes > 0;
}

std::string getErrorMessage(const std::string &jsonStr)
{
    // Find the position of the "message" key in the string
    size_t pos = jsonStr.find("\"message\":\"");
    if (pos != std::string::npos)
    {
        // Extract the substring starting right after "\"message\":\""
        size_t start = pos + 11; // 11 is the length of "\"message\":\""
        size_t end = jsonStr.find("\"", start);

        // Return the substring that contains the error message
        return jsonStr.substr(start, end - start);
    }
    return "No error message found.";
}

using json = nlohmann::json;
void printJson(const std::string &jsonStr)
{
    try
    {
        // Parse the JSON string into a JSON object
        json j = json::parse(jsonStr);
        // Iterate over each element in the JSON object
        for (auto &element : j.items())
        {
            // Print the key and value for each item
            std::cout << "Key: " << element.key() << ", Value: " << element.value() << std::endl;
        }
    }
    catch (const json::parse_error &e)
    {
        std::cerr << "Error parsing JSON: " << e.what() << std::endl;
    }
}

#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define CYAN "\033[0;36m"
#define RESET "\033[0m"

bool isError(const std::string &response)
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
                // return element.value();
            }
        }
    }
    catch (const json::parse_error &e)
    {
        std::cerr << "Error parsing JSON: " << e.what() << std::endl;
    }
    return false;
}

void authenticate(Connection &con)
{
    const char *client_id = CLIENT_ID;
    const char *client_secret = CLIENT_SECRET;

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

    if (!sendMessage(con, message.str()))
        throw Error("failed to authenticate");

    std::string response;
    if (receiveMessage(con, response))
    {
        if (isError(response)) std::cout << RED << "Failed to authenticate" << RESET << std::endl;
        else std::cout << GREEN << "Authenticated succefully " << RESET << std::endl;
    }
}

void clear_connection(Connection &con)
{
    SSL_CTX_free(con.ctx);
    EVP_cleanup();
    SSL_shutdown(con.ssl);
    SSL_free(con.ssl);
}

int main()
{
    try
    {
        Connection con;
        con.url = DERIBIT_URL;
        con.path = DERIBIT_PATH;
        std::cout << "before connection" << std::endl;
        _connect(con);
        std::cout << "after connection" << std::endl;
        authenticate(con);

        clear_connection(con);
    }
    catch (Error &error)
    {
        std::cerr << "Error: " << error.what() << std::endl;
    }
}