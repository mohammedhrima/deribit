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
#include <openssl/rand.h>
#include <openssl/evp.h>
// #include <boost/random.hpp>
// #include <boost/archive/iterators/base64_from_binary.hpp>
// #include <boost/archive/iterators/binary_from_base64.hpp>

#define CLIENT_ID "6ljNdSET"
#define CLIENT_SECRET "R08jkZ_yC7yzHfrl1o0MXxIlSZwmJ-AaboLOJqcNCgM"
#define DRIBLE_URL "test.deribit.com"
#define DRIBLE_API "/ws/api/v2"
#define DRIBLE_PORT 443

#define TEXT_FRAME (uint8_t)0x81
#define MASK_BIT (uint8_t)0x80
#define PAYLOAD_16BIT (uint8_t)126
#define PAYLOAD_64BIT (uint8_t)127

#define BUFFER_SIZE 4096
#define PORT 17000
typedef struct sockaddr_in sockaddr_in;
typedef struct hostent hostent;

class Error : public std::exception
{
private:
    std::string message;

public:
    Error(const std::string message_) : message(message_) {};
    ~Error() {};
    const char *what() const throw()
    {
        return message.c_str();
    };
};

class Base64
{

public:
    static std::string encode(const unsigned char *bytes_to_encode, size_t in_len)
    {
        std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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
};

class Client
{

public:
#define check(cond, message)  \
    if (cond)                 \
    {                         \
        disconnect();         \
        throw Error(message); \
    }

    int fd;
    std::string url;
    std::string path;
    size_t port;
    SSL_CTX *ctx;
    SSL *ssl;

    // constructors
    Client(const std::string &url_, const std::string &path_, const size_t &port_) : url(url_), path(path_), port(port_), fd(-1), ssl(nullptr), ctx(nullptr)
    {
        init_ssl();
    }

    std::string generateWebSocketKey()
    {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);

        unsigned char random_bytes[16];
        for (int i = 0; i < 16; ++i)
            random_bytes[i] = static_cast<unsigned char>(dis(gen));
        return Base64::encode(random_bytes, 16);
    }
    // methods
    void init_ssl()
    {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();

        const SSL_METHOD *method = TLS_client_method();
        ctx = SSL_CTX_new(method);

        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        SSL_CTX_set_verify_depth(ctx, 4);
        SSL_CTX_load_verify_locations(ctx, nullptr, "/etc/ssl/certs");
    }

    void init_connection()
    {
        fd = socket(AF_INET, SOCK_STREAM, 0);
        check(fd < 0, "failed to create socket");

        int option = 1;
        check(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &option, sizeof(option)), "setsockopt failed");

        // resolve hostname
        hostent *host = gethostbyname(url.c_str());
        check(!host, "failed to resolve hostname");

        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        memcpy(&addr.sin_addr, host->h_addr_list[0], host->h_length);

        check(::connect(fd, (sockaddr *)&addr, sizeof(addr)) < 0, "Connection failed");
    }

    void setup_ssl()
    {
        X509 *cert;

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fd);
        SSL_set_tlsext_host_name(ssl, url.c_str());

        check(SSL_connect(ssl) <= 0, "SSL handshake failed");

        cert = SSL_get_peer_certificate(ssl);
        check(!cert, "No certificate presented by server");
        X509_free(cert);
    }

    void handshake()
    {
        std::string key = generateWebSocketKey();
        std::ostringstream request;

        request << "GET " << path << " HTTP/1.1\r\n"
                << "Host: " << url << "\r\n"
                << "Upgrade: websocket\r\n"
                << "Connection: Upgrade\r\n"
                << "Sec-WebSocket-Key: " << key << "\r\n"
                << "Sec-WebSocket-Version: 13\r\n\r\n";

        check(SSL_write(ssl, request.str().c_str(), request.str().size()) <= 0, "Failed to send WebSocket handshake");

        char response[BUFFER_SIZE + 1] = {0};
        check(SSL_read(ssl, response, BUFFER_SIZE) <= 0, "Failed to read handshake response");
        check(std::string(response).find("101 Switching Protocols") == std::string::npos, "WebSocket upgrade failed");
    }

    void connect()
    {
        init_connection();
        setup_ssl();
        handshake();
    }

    // IO
    std::vector<uint8_t> mask_data(const std::string &payload)
    {
        std::vector<uint8_t> masked;
        std::random_device rd;
        uint8_t mask[4];
        for (int i = 0; i < 4; ++i)
            mask[i] = rd() & 0xFF;
        masked.reserve(payload.size() + 4);
        masked.insert(masked.end(), mask, mask + 4);
        for (size_t i = 0; i < payload.size(); ++i)
            masked.push_back(payload[i] ^ mask[i % 4]);

        return masked;
    }

    int send(const std::string &message)
    {
        // create frame
        std::vector<uint8_t> frame;
        frame.push_back(TEXT_FRAME);

        if (message.size() <= 125)
            frame.push_back(message.size());
        else if (message.size() <= 65535)
        {
            frame.push_back(PAYLOAD_16BIT);
            frame.push_back((message.size() >> 8) & 0xFF);
            frame.push_back(message.size() & 0xFF);
        }
        frame.insert(frame.end(), message.begin(), message.end());

        return SSL_write(ssl, frame.data(), frame.size());
    }

    bool receive(std::string &message)
    {
        std::cout << "recieved message: " << message << std::endl;
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

    void disconnect()
    {
        if (fd > 0)
        {
            close(fd);
            fd = -1;
        }
        if (ctx)
        {
            SSL_CTX_free(ctx);
            ctx = nullptr;
        }
        if (ssl)
        {
            SSL_free(ssl);
            ssl = nullptr;
        }
    }
    // destructor
    ~Client()
    {
        disconnect();
    }
};

int main()
{
    try
    {
        Client client(DRIBLE_URL, DRIBLE_API, DRIBLE_PORT);
        client.connect();
        std::cout << "connected succefully" << std::endl;
        std::string message = "Hello, WebSocket!";
        if (client.send(message) <= 0)
            throw Error("send failed");

        std::ostringstream message_stream;
        message_stream << R"({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "public/auth",
        "params": {
            "grant_type": "client_credentials",
            "client_id": ")"
                       << CLIENT_ID << R"(",
            "client_secret": ")"
                       << CLIENT_SECRET << R"("
        }
    })";

        if (client.send(message_stream.str()) <= 0)
        {
            std::cout << "failed to authenticate " << std::endl;
        }
        std::string response;
        if (client.receive(response))
            std::cout << "response: " << response << std::endl;
    }
    catch (Error &error)
    {
        std::cerr << error.what() << std::endl;
    }
}