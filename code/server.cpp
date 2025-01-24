#include "./includes/header.hpp"

Server::Server(int port_) : port(port_) {}

void Server::init()
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

void Server::sendResponse(int client_fd, int statusCode, const std::string &body, std::string content_type = "text/plain")
{
    std::string statusText = (statusCode == 200) ? "OK" : "Bad Request";
    std::string response =
        "HTTP/1.1 " + std::to_string(statusCode) + " " + statusText + "\r\n" +
        "Content-Length: " + std::to_string(body.size()) + "\r\n" +
        "Content-Type: " + content_type + "\r\n" +
        "\r\n" + body;

    send(client_fd, response.c_str(), response.size(), 0);
}

void Server::serve_static_file(int client_fd, Request &req)
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

void Server::start(Api &api)
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
                        std::cout << "url:" << req.url << std::endl;
                        std::cout << "method:" << req.method << std::endl;
                        if (req.url == "/api/login" && req.method == "POST")
                        {
                            std::map<std::string, std::string> params = parse_query_string(req.body);
                            if (api.authenticate(params["client_id"], params["client_secret"]))
                                sendResponse(client_fd, 200, generate_html(200, "logged in succefully"), "text/html");
                            else
                                sendResponse(client_fd, 500, generate_html(500, "Invalid credentials"), "text/html");
                        }
                        else if (req.url == "/api/place_order" && req.method == "POST")
                        {
                            std::map<std::string, std::string> params = parse_query_string(req.body);
                            if (api.place_order(params["instrument"], to_double(params["amount"]), to_double(params["price"]), params["type"]))
                                sendResponse(client_fd, 200, generate_html(200, "order placed succefully"), "text/html");
                            else
                                sendResponse(client_fd, 500, generate_html(500, "error placing order"), "text/html");
                        }
                        else if (req.url == "/api/modify_order" && req.method == "POST")
                        {
                            std::map<std::string, std::string> params = parse_query_string(req.body);
                            if (api.modify_order(params["order_id"], to_double(params["amount"]), to_double(params["price"])))
                                sendResponse(client_fd, 200, generate_html(200, "order modified succefully"), "text/html");
                            else
                                sendResponse(client_fd, 500, generate_html(500, "error modifying order"), "text/html");
                        }
                        else if (req.url == "/api/cancel_order" && req.method == "POST")
                        {
                            std::map<std::string, std::string> params = parse_query_string(req.body);
                            if (api.cancel_order(params["order_id"]))
                                sendResponse(client_fd, 200, generate_html(200, "order canceled succefully"), "text/html");
                            else
                                sendResponse(client_fd, 500, generate_html(500, "error canceling order"), "text/html");
                        }
                        else if (req.url == "/api/get_order_book" && req.method == "POST")
                        {
                            std::map<std::string, std::string> params;
                            json j = json::parse(req.body);
                            for (auto &element : j.items())
                                params[element.key()] = element.value();
                            std::string response;
                            if (api.get_order_book(params["instrument_name"], 3, response))
                                sendResponse(client_fd, 200, response, "application/json");
                            else
                                sendResponse(client_fd, 500, generate_html(500, "error get order book"), "text/html");
                        }
                        else if (req.url == "/api/get_positions" && req.method == "POST")
                        {
                            std::map<std::string, std::string> params;
                            json j = json::parse(req.body);
                            for (auto &element : j.items())
                                params[element.key()] = element.value();
                            std::string response;
                            if (api.get_positions(params["currency"], response))
                                sendResponse(client_fd, 200, response, "application/json");
                            else
                                sendResponse(client_fd, 500, generate_html(500, "error get position book"), "text/html");
                        }
                        else
                            sendResponse(client_fd, 500, generate_html(404, "Invalid request"), "text/html");
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

Server::~Server()
{
}