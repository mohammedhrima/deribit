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

// Base64 encoding implementation
class Base64
{
private:
    static const std::string base64_chars;

public:
    static std::string encode(const unsigned char *bytes_to_encode, size_t in_len)
    {
        std::string ret;
        int i = 0;
        int j = 0;
        unsigned char char_array_3[3];
        unsigned char char_array_4[4];

        while (in_len--)
        {
            char_array_3[i++] = *(bytes_to_encode++);
            if (i == 3)
            {
                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;

                for (i = 0; i < 4; i++)
                    ret += base64_chars[char_array_4[i]];
                i = 0;
            }
        }

        if (i)
        {
            for (j = i; j < 3; j++)
                char_array_3[j] = '\0';

            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (j = 0; j < i + 1; j++)
                ret += base64_chars[char_array_4[j]];

            while (i++ < 3)
                ret += '=';
        }

        return ret;
    }
};

const std::string Base64::base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

class WebSocketClient
{
private:
    SSL_CTX *ctx;
    SSL *ssl;
    int sock;
    std::string server_url;
    int server_port;
    std::string path;

    // Generate random WebSocket key
    std::string generateWebSocketKey()
    {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);

        unsigned char random_bytes[16];
        for (int i = 0; i < 16; ++i)
        {
            random_bytes[i] = static_cast<unsigned char>(dis(gen));
        }

        return Base64::encode(random_bytes, 16);
    }

    // Mask WebSocket frame
    std::vector<uint8_t> maskData(const std::string &payload)
    {
        std::vector<uint8_t> masked;
        std::random_device rd;
        uint8_t mask[4];
        for (int i = 0; i < 4; ++i)
        {
            mask[i] = rd() & 0xFF;
        }

        masked.reserve(payload.size() + 4);
        masked.insert(masked.end(), mask, mask + 4);

        for (size_t i = 0; i < payload.size(); ++i)
        {
            masked.push_back(payload[i] ^ mask[i % 4]);
        }

        return masked;
    }

    // Create WebSocket frame
    std::vector<uint8_t> createFrame(const std::string &payload)
    {
        std::vector<uint8_t> frame;
        frame.push_back(0x81); // Text frame

        auto masked_payload = maskData(payload);

        if (payload.size() <= 125)
        {
            frame.push_back(0x80 | payload.size()); // Set masked bit and payload length
        }
        else if (payload.size() <= 65535)
        {
            frame.push_back(0x80 | 126);
            frame.push_back((payload.size() >> 8) & 0xFF);
            frame.push_back(payload.size() & 0xFF);
        }
        else
        {
            frame.push_back(0x80 | 127);
            for (int i = 7; i >= 0; --i)
            {
                frame.push_back((payload.size() >> (i * 8)) & 0xFF);
            }
        }

        frame.insert(frame.end(), masked_payload.begin(), masked_payload.end());
        return frame;
    }

public:
    WebSocketClient(const std::string &url, int port, const std::string &ws_path)
        : server_url(url), server_port(port), path(ws_path), sock(-1), ssl(nullptr)
    {
        // Initialize OpenSSL
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();

        const SSL_METHOD *method = TLS_client_method();
        ctx = SSL_CTX_new(method);

        // Set up certificate verification
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        SSL_CTX_set_verify_depth(ctx, 4);
        SSL_CTX_load_verify_locations(ctx, nullptr, "/etc/ssl/certs");
    }

    ~WebSocketClient()
    {
        disconnect();
        SSL_CTX_free(ctx);
        EVP_cleanup();
    }

    bool connect()
    {
        // Create socket
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0)
        {
            std::cerr << "Socket creation failed" << std::endl;
            return false;
        }

        // Set timeout
        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        // Resolve hostname
        struct hostent *host = gethostbyname(server_url.c_str());
        if (!host)
        {
            std::cerr << "DNS resolution failed" << std::endl;
            close(sock);
            return false;
        }

        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(server_port);
        memcpy(&server_addr.sin_addr, host->h_addr_list[0], host->h_length);

        // Connect
        if (::connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        {
            std::cerr << "Connection failed" << std::endl;
            close(sock);
            return false;
        }

        // Set up SSL
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);
        SSL_set_tlsext_host_name(ssl, server_url.c_str()); // Set SNI

        if (SSL_connect(ssl) <= 0)
        {
            std::cerr << "SSL handshake failed" << std::endl;
            SSL_free(ssl);
            close(sock);
            return false;
        }

        // Verify certificate
        X509 *cert = SSL_get_peer_certificate(ssl);
        if (!cert)
        {
            std::cerr << "No certificate presented by server" << std::endl;
            disconnect();
            return false;
        }
        X509_free(cert);

        // Perform WebSocket handshake
        std::string ws_key = generateWebSocketKey();
        std::ostringstream request;
        request << "GET " << path << " HTTP/1.1\r\n"
                << "Host: " << server_url << "\r\n"
                << "Upgrade: websocket\r\n"
                << "Connection: Upgrade\r\n"
                << "Sec-WebSocket-Key: " << ws_key << "\r\n"
                << "Sec-WebSocket-Version: 13\r\n\r\n";

        if (SSL_write(ssl, request.str().c_str(), request.str().size()) <= 0)
        {
            std::cerr << "Failed to send WebSocket handshake" << std::endl;
            disconnect();
            return false;
        }

        // Read handshake response
        char response[4096] = {0};
        int bytes = SSL_read(ssl, response, sizeof(response) - 1);
        if (bytes <= 0)
        {
            std::cerr << "Failed to read handshake response" << std::endl;
            disconnect();
            return false;
        }

        if (std::string(response).find("101 Switching Protocols") == std::string::npos)
        {
            std::cerr << "WebSocket upgrade failed" << std::endl;
            disconnect();
            return false;
        }

        return true;
    }

    void disconnect()
    {
        if (ssl)
        {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            ssl = nullptr;
        }
        if (sock >= 0)
        {
            close(sock);
            sock = -1;
        }
    }

    bool send(const std::string &message)
    {
        auto frame = createFrame(message);
        return SSL_write(ssl, frame.data(), frame.size()) > 0;
    }

    bool receive(std::string &message)
    {
        uint8_t header[2];
        int bytes = SSL_read(ssl, header, 2);
        if (bytes <= 0)
            return false;

        if (!(header[0] & 0x80))
        {
            std::cerr << "Fragmented messages not supported" << std::endl;
            return false;
        }

        uint8_t opcode = header[0] & 0x0F;
        uint8_t masked = header[1] & 0x80;
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
        bytes = SSL_read(ssl, payload.data(), payload_length);
        if (bytes <= 0)
            return false;

        message = std::string(payload.begin(), payload.end());
        return true;
    }
};

const std::string SERVER_URL = "test.deribit.com";
const int SERVER_PORT = 443;
const std::string WEBSOCKET_PATH = "/ws/api/v2";
const std::string CLIENT_ID = "6ljNdSET";
const std::string CLIENT_SECRET = "R08jkZ_yC7yzHfrl1o0MXxIlSZwmJ-AaboLOJqcNCgM";

int sendMessage(WebSocketClient &client, std::ostringstream &message)
{
    if (!client.send(message.str()))
    {
        std::cerr << "Failed to send auth message" << std::endl;
        return 1;
    }
    return 0;
}

int placeOrder(WebSocketClient &client, const std::string &instrument, double amount, double price, const std::string &type = "limit")
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
            <<  amount << R"(,
            "type": ")"
            << type << R"(",
            "price": )"
            <<  price << R"(
        }
    })";

    return sendMessage(client, message);
}

int authenticate(WebSocketClient &client)
{
    const char *client_id = CLIENT_ID.c_str();
    const char *client_secret = CLIENT_SECRET.c_str();
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

    return sendMessage(client, message);
}

// Example usage
int main()
{
    WebSocketClient client("test.deribit.com", 443, "/ws/api/v2");
    if (!client.connect())
    {
        std::cerr << "Failed to connect" << std::endl;
        return 1;
    }

    if (authenticate(client)) return 1;
    std::string response;
    if (client.receive(response)) std::cout << "Connect: " << response << std::endl;
    if(placeOrder(client, "BTC-PERPETUAL", 10.0, 25000)) return 1;
    if (client.receive(response)) std::cout << "Place order: " << response << std::endl;

    return 0;
}
