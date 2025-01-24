#include "header.hpp"

bool starts_with(const std::string &str, const std::string &prefix)
{
    return str.size() >= prefix.size() && str.compare(0, prefix.size(), prefix) == 0;
}

// deribit api
typedef struct timeval timeval;
typedef struct hostent hostent;
typedef struct sockaddr_in sockaddr_in;

std::string trim(const std::string s)
{
    size_t start = s.find_first_not_of(" \t\n");
    size_t end = s.find_last_not_of(" \t\n");
    return (start == std::string::npos) ? s : s.substr(start, end - start + 1);
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

    std::string last_pair = trim(query.substr(start));
    size_t equal_pos = last_pair.find('=');
    if (equal_pos != std::string::npos)
    {
        std::string key = last_pair.substr(0, equal_pos);
        std::string value = last_pair.substr(equal_pos + 1);
        params[key] = value;
    }
    std::cout << RED << "queries: [" << query << "]" << std::endl;
    return params;
}

class Request
{
public:
    std::string method;
    std::string url;
    std::map<std::string, std::string> headers;
    std::string body;
    bool is_api;

    Request(const std::string buffer)
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
    ~Request() {};

    void parse()
    {
    }
};

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
    Api(std::string _path, std::string _url, size_t _port) : path(_path), url(_url), port(_port) {};
    ~Api()
    {
        SSL_CTX_free(ctx);
        EVP_cleanup();
        SSL_shutdown(ssl);
        SSL_free(ssl);
    };
    void init()
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
    void handshake()
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
    int sendMessage(std::string message)
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
    int receiveMessage(std::string &message)
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
        if ((bytes = SSL_read(ssl, payload.data(), payload_length)) <= 0)
            return bytes;

        message = std::string(payload.begin(), payload.end());
        return bytes > 0;
    }
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
                }
            }
        }
        catch (const json::parse_error &e)
        {
            std::cerr << "Error parsing JSON: " << e.what() << std::endl;
        }
        return false;
    }

    bool authenticate(std::string client_id, std::string client_secret)
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
            throw Error("failed to sendMessage to api");

        std::string response;
        if (receiveMessage(response))
        {
            if (isError(response))
            {
                std::cout << RED << "Failed to authenticate" << RESET << std::endl;
            }
            else
            {
                std::cout << GREEN << "Authenticated succefully " << RESET << std::endl;
                return true;
            }
        }
        return false;
    }
    
};

std::string generate_html(int status_code, const std::string &cause)
{
    std::ostringstream html;

    html << "<!DOCTYPE html>\n"
         << "<html lang=\"en\">\n"
         << "<head>\n"
         << "    <meta charset=\"UTF-8\">\n"
         << "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
         << "    <title>Error " << status_code << "</title>\n"
         << "    <style>\n"
         << "        body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0; }\n"
         << "        .container { text-align: center; padding: 50px; }\n"
         << "        h1 { font-size: 50px; color: #333; }\n"
         << "        p { font-size: 20px; color: #666; }\n"
         << "    </style>\n"
         << "</head>\n"
         << "<body>\n"
         << "    <div class=\"container\">\n";

    // Correctly handle the conditional logic
    if (status_code > 200)
        html << "        <h1>Error " << status_code << "</h1>\n";
    else
        html << "        <h1>" << status_code << "</h1>\n";

    html << "        <p>" << cause << "</p>\n"
         << "    </div>\n"
         << "</body>\n"
         << "</html>\n";

    return html.str();
}

class Server
{
private:
    int fd;
    size_t port;

public:
    Server(int port_) : port(port_) {}
    void init()
    {
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd == -1)
            throw Error("Failed to create server socket.");

        int opt = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) == -1)
        {
            close(fd);
            throw Error("Failed to set server sockopt");
        }

        sockaddr_in address;
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port);

        if (bind(fd, (sockaddr *)&address, sizeof(address)) == -1)
            throw Error("Failed to bind server socket.");

        if (listen(fd, 10) == -1)
            throw Error("Failed to listen on socket.");
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
    // UTILS
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

    void serve_static_file(int client_fd, Request &req)
    {
        std::string filepath = "./public/";
        int status = 200;
        std::ifstream file;

        if (req.method == "GET")
        {
            if (req.url == "/")
                filepath += "index.html";
            else
                filepath += req.url;

            file.open(filepath.c_str(), std::ios::in | std::ios::binary);
            if (!file)
            {
                status = 404;
                filepath = "./public/404.html";
                file.open(filepath.c_str(), std::ios::in | std::ios::binary);
            }
        }
        else
        {
            status = 400;
            filepath = "./public/400.html";
            file.open(filepath.c_str(), std::ios::in | std::ios::binary);
        }

        std::ostringstream contentStream;
        if (file)
        {
            contentStream << file.rdbuf();
            file.close();
        }

        std::string content = contentStream.str();
        sendResponse(client_fd, status, content, "text/html");
    }

    void start(Api &api)
    {
        int epoll_fd = epoll_create1(0);
        if (epoll_fd == -1)
        {
            close(fd);
            throw Error("Failed to create epoll instance.");
        }

        epoll_event event;
        event.events = EPOLLIN;
        event.data.fd = fd;

        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) == -1)
        {
            close(fd);
            close(epoll_fd);
            throw Error("Failed to add server socket to epoll.");
        }

        epoll_event events[MAX_EPOLL_EVENTS];
        std::cout << "Server running on port " << PORT << "...\n";

        while (true)
        {
            int size = epoll_wait(epoll_fd, events, MAX_EPOLL_EVENTS, -1);
            if (size == -1)
            {
                std::cerr << "epoll_wait failed." << std::endl;
                break;
            }

            for (int i = 0; i < size; ++i)
            {
                if (events[i].data.fd == fd)
                {
                    // Accept a new client connection
                    sockaddr_in client_address;
                    socklen_t client_len = sizeof(client_address);
                    int client_fd = accept(fd, (sockaddr *)&client_address, &client_len);
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
                    int client_fd = events[i].data.fd;

                    char buff[BUFFERSIZE];
                    memset(buff, 0, sizeof(buff));

                    int bytes = read(client_fd, buff, sizeof(buff) - 1);
                    if (bytes > 0)
                    {
                        std::string str = buff;
                        Request req(str); // parse request

                        if (req.is_api)
                        {
                            // handle APi
                            if (req.url == "/api/auth" && req.method == "POST")
                            {
                                std::map<std::string, std::string> params = parse_query_string(req.body);
                                if (api.authenticate(std::string(params["client_id"]), std::string(params["client_secret"])))
                                    sendResponse(client_fd, 200, generate_html(200, "logged in succefully"), "text/html");
                                else
                                    sendResponse(client_fd, 500, generate_html(500, "could not logged in"), "text/html");
                            }
                            else
                                sendResponse(client_fd, 500, generate_html(500, "failed to login"), "text/html");
                        }
                        else
                        {
                            // serve static file
                            serve_static_file(client_fd, req);
                        }
                    }
                    close(client_fd);
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_fd, nullptr);
                }
            }
        }

        close(epoll_fd);
        close(fd);
    }
    ~Server()
    {
    }
};

int main()
{
    try
    {
        Api api(DERIBIT_PATH, DERIBIT_URL, DERIBIT_PORT);

        api.init();
        api.handshake();
        // api.authenticate(CLIENT_ID, CLIENT_SECRET);

        Server server(PORT);
        server.init();
        server.start(api);
    }
    catch (Error &error)
    {
        std::cerr << "Error: " << error.what() << std::endl;
    }
}