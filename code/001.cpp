#include <iostream>
#include <cstring>
#include <string>
#include <sstream>
#include <map>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <fstream>
#include <string>
#include <sstream>
#include <map>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <fstream>
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

#define PORT 17000
#define BUFFERSIZE 8192
#define MAX_EVENTS 10

#define CLIENT_ID "6ljNdSET"
#define CLIENT_SECRET "R08jkZ_yC7yzHfrl1o0MXxIlSZwmJ-AaboLOJqcNCgM"
#define DERIBIT_URL "test.deribit.com"
#define DERIBIT_PATH "/ws/api/v2"
#define DERIBIT_PORT 443

#define MAX_CONNECTIONS 10

// deribit api
typedef struct timeval timeval;
typedef struct hostent hostent;
typedef struct sockaddr_in sockaddr_in;
typedef struct Connection Connection;
struct Connection
{
    int fd;
    SSL *ssl;
    SSL_CTX *ctx;
    std::string url;
    std::string path;
};

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

void start_connection(Connection &con)
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

void authenticate(Connection &con, std::string client_id, std::string client_secret)
{
    std::ostringstream message;
    message << R"({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "public/auth",
        "params": {
            "grant_type": "client_credentials",
            "client_id": ")"
            << client_id.c_str() << R"(",
            "client_secret": ")"
            << client_secret.c_str() << R"("
        }
    })";

    if (!sendMessage(con, message.str()))
        throw Error("failed to authenticate");

    std::string response;
    if (receiveMessage(con, response))
    {
        if (isError(response))
            std::cout << RED << "Failed to authenticate" << RESET << std::endl;
        else
            std::cout << GREEN << "Authenticated succefully " << RESET << std::endl;
    }
}

void clear_connection(Connection &con)
{
    SSL_CTX_free(con.ctx);
    EVP_cleanup();
    SSL_shutdown(con.ssl);
    SSL_free(con.ssl);
}

// local webserver
int init_server(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1)
    {
        std::cerr << "Error: Failed to create socket.\n";
        return -1;
    }

    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) == -1)
    {
        std::cerr << "Error: Failed to set SO_REUSEADDR.\n";
        close(fd);
        return -1;
    }

    sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(fd, (sockaddr *)&address, sizeof(address)) == -1)
    {
        std::cerr << "Error: Failed to bind socket.\n";
        return -1;
    }

    if (listen(fd, 10) == -1)
    {
        std::cerr << "Error: Failed to listen on socket.\n";
        return -1;
    }

    return fd;
}

struct Request
{
    std::string method;
    std::string url;
    std::map<std::string, std::string> headers;
    std::string body;
};

std::ostream &operator<<(std::ostream &os, const Request &req)
{
    os << "method: " << req.method << "\n";
    os << "url: " << req.url << "\n";
    os << "headers:\n";
    for (const auto &header : req.headers)
    {
        os << "  " << header.first << ": " << header.second << "\n";
    }
    os << "body: " << req.body << "\n";
    return os;
}

std::string trim(const std::string &s)
{
    size_t start = s.find_first_not_of(" ");
    size_t end = s.find_last_not_of(" ");
    return (start == std::string::npos) ? s : s.substr(start, end - start + 1);
}

Request parse_request(const std::string &buffer)
{
    Request req;
    std::istringstream stream(buffer);
    std::string line;

    std::getline(stream, line);
    std::istringstream reqline(line);
    reqline >> req.method >> req.url;

    while (std::getline(stream, line) && line != "\r")
    {
        size_t pos = line.find(":");
        if (pos != std::string::npos)
        {
            std::string key = trim(line.substr(0, pos));
            std::string value = trim(line.substr(pos + 2));
            req.headers[key] = value;
        }
    }

    std::string body;
    while (std::getline(stream, line))
        body += line + "\n";
    req.body = body;
    return req;
}

void sendResponse(int client_fd, int statusCode, const std::string &body, std::string content_type = "text/plain")
{
    std::string statusText = (statusCode == 200) ? "OK" : "Bad Request";
    std::string response =
        "HTTP/1.1 " + std::to_string(statusCode) + " " + statusText + "\r\n" +
        "Content-Length: " + std::to_string(body.size()) + "\r\n" +
        "Content-Type: " + content_type + "\r\n" +
        "\r\n" + body;

    send(client_fd, response.c_str(), response.size(), 0);
}

std::string get_mime_type(const std::string &path)
{
    size_t dot_pos = path.rfind('.');
    if (dot_pos == std::string::npos)
    {
        return "application/octet-stream";
    }

    std::string extension = path.substr(dot_pos);

    if (extension == ".html")
        return "text/html";
    if (extension == ".css")
        return "text/css";
    if (extension == ".js")
        return "application/javascript";
    if (extension == ".json")
        return "application/json";
    if (extension == ".jpg" || extension == ".jpeg")
        return "image/jpeg";
    if (extension == ".png")
        return "image/png";
    if (extension == ".gif")
        return "image/gif";
    if (extension == ".svg")
        return "image/svg+xml";

    return "application/octet-stream";
}

std::map<std::string, std::string> parse_query_string(const std::string &query)
{
    std::map<std::string, std::string> params;

    size_t start = 0;
    size_t end = query.find('&');

    while (end != std::string::npos)
    {
        std::string pair = query.substr(start, end - start);

        size_t equal_pos = pair.find('=');
        if (equal_pos != std::string::npos)
        {
            std::string key = pair.substr(0, equal_pos);
            std::string value = pair.substr(equal_pos + 1);
            params[key] = value;
        }

        start = end + 1;
        end = query.find('&', start);
    }

    std::string last_pair = query.substr(start);
    size_t equal_pos = last_pair.find('=');
    if (equal_pos != std::string::npos)
    {
        std::string key = last_pair.substr(0, equal_pos);
        std::string value = last_pair.substr(equal_pos + 1);
        params[key] = value;
    }

    return params;
}

void handleRequest(Connection &con, int client_fd)
{
    char buffer[BUFFERSIZE];
    memset(buffer, 0, sizeof(buffer));

    int bytesRead = read(client_fd, buffer, sizeof(buffer) - 1);
    if (bytesRead > 0)
    {
        std::string request(buffer);
        Request req = parse_request(request);
        std::cout << "received: " << req << std::endl;

        if (req.method == "GET")
        {

            std::string filepath = ".";

            if (req.url == "/")
                filepath += "/index.html";
            else
                filepath += req.url;
            std::ifstream file(filepath, std::ios::in | std::ios::binary);
            if (file)
            {
                std::ostringstream contentStream;
                contentStream << file.rdbuf();
                std::string content = contentStream.str();
                file.close();

                sendResponse(client_fd, 200, content, get_mime_type(filepath));
            }
            else
            {
                sendResponse(client_fd, 404, "Error: File not found.");
            }
        }
        else if (req.method == "POST")
        {
            if (req.url == "/api/auth")
            {
                std::cout << "auth with: " << std::endl;
                std::map<std::string, std::string> params = parse_query_string(req.body);
                for (std::map<std::string, std::string>::iterator it = params.begin(); it != params.end(); ++it)
                    std::cout << it->first << " : " << it->second << std::endl;
                authenticate(con, params["client_id"], params["client_secret"]);
            }
            else
                sendResponse(client_fd, 200, "POST request received: " + req.body);
        }
        else if (req.method == "DELETE")
        {
            sendResponse(client_fd, 200, "DELETE request received.");
        }
        else
        {
            sendResponse(client_fd, 400, "Unsupported method.");
        }
    }
}

void start_server(Connection &con, int server_fd)
{
    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1)
    {
        std::cerr << "Error: Failed to create epoll instance.\n";
        close(server_fd);
        return;
    }

    epoll_event event;
    event.events = EPOLLIN;
    event.data.fd = server_fd;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &event) == -1)
    {
        std::cerr << "Error: Failed to add server socket to epoll.\n";
        close(server_fd);
        close(epoll_fd);
        return;
    }

    epoll_event events[MAX_EVENTS];
    std::cout << "Server running on port " << PORT << "...\n";

    while (true)
    {
        int eventCount = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (eventCount == -1)
        {
            std::cerr << "Error: epoll_wait failed.\n";
            break;
        }

        for (int i = 0; i < eventCount; ++i)
        {
            if (events[i].data.fd == server_fd)
            {
                // Accept a new client connection
                sockaddr_in client_address;
                socklen_t client_len = sizeof(client_address);
                int client_fd = accept(server_fd, (sockaddr *)&client_address, &client_len);

                if (client_fd == -1)
                {
                    std::cerr << "Error: Failed to accept connection.\n";
                    continue;
                }

                // Add the new client to epoll
                epoll_event clientEvent;
                clientEvent.events = EPOLLIN;
                clientEvent.data.fd = client_fd;

                if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &clientEvent) == -1)
                {
                    std::cerr << "Error: Failed to add client socket to epoll.\n";
                    close(client_fd);
                    continue;
                }
            }
            else
            {
                // Handle client request
                int client_fd = events[i].data.fd;
                handleRequest(con, client_fd);

                // Close client connection and remove it from epoll
                close(client_fd);
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_fd, nullptr);
            }
        }
    }

    close(epoll_fd);
    close(server_fd);
}

int main()
{
    Connection con;
    con.url = DERIBIT_URL;
    con.path = DERIBIT_PATH;

    start_connection(con);

    int fd = init_server(PORT);
    if (fd < 0)
        return 1;
    start_server(con, fd);
    clear_connection(con);
}