#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

class WebSocketClient
{
private:
    int sock;
    std::string server_url;
    int server_port;
    std::string path;

    std::string generateWebSocketKey()
    {
        return "dGhlIHNhbXBsZSBub25jZQ=="; // Simplified hardcoded key
    }
public:
    WebSocketClient(const std::string &url, int port, const std::string &ws_path) : server_url(url), server_port(port), path(ws_path), sock(-1)
    {
    }

    ~WebSocketClient()
    {
        disconnect();
    }

    bool connect()
    {
        // Create socket
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0)
        {
            std::cerr << "Socket creation failed\n";
            return false;
        }

        // Resolve hostname
        struct hostent *host = gethostbyname(server_url.c_str());
        if (!host)
        {
            std::cerr << "DNS resolution failed\n";
            close(sock);
            return false;
        }

        // Connect to server
        struct sockaddr_in server_addr = {};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(server_port);
        memcpy(&server_addr.sin_addr, host->h_addr_list[0], host->h_length);

        if (::connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        {
            std::cerr << "Connection failed\n";
            close(sock);
            return false;
        }

        std::string ws_key = generateWebSocketKey();
        std::string request =
            "GET " + path + " HTTP/1.1\r\n"
                            "Host: " +
            server_url + "\r\n"
                         "Upgrade: websocket\r\n"
                         "Connection: Upgrade\r\n"
                         "Sec-WebSocket-Key: " +
            ws_key + "\r\n"
                     "Sec-WebSocket-Version: 13\r\n\r\n";

        // Send handshake request
        if (::send(sock, request.c_str(), request.size(), 0) <= 0)
        {
            std::cerr << "Failed to send handshake request\n";
            return false;
        }

        // Receive handshake response
        char response[4096] = {0};
        if (recv(sock, response, sizeof(response) - 1, 0) <= 0)
        {
            std::cerr << "Failed to receive handshake response\n";
            return false;
        }

        // Check for "101 Switching Protocols"
        // if (std::string(response).find("101 Switching Protocols") == std::string::npos)
        // {
        //     std::cerr << "WebSocket upgrade failed\n";
        //     return false;
        // }

        return true;
    }

    void disconnect()
    {
        if (sock >= 0)
        {
            close(sock);
            sock = -1;
        }
    }

    bool send(const std::string &message)
    {
        std::vector<uint8_t> frame;
        frame.push_back(0x81); // Text frame opcode

        // Payload length
        if (message.size() <= 125)
        {
            frame.push_back(message.size());
        }
        else if (message.size() <= 65535)
        {
            frame.push_back(126);
            frame.push_back((message.size() >> 8) & 0xFF);
            frame.push_back(message.size() & 0xFF);
        }

        // Add payload
        frame.insert(frame.end(), message.begin(), message.end());

        return ::send(sock, frame.data(), frame.size(), 0) > 0;
    }

    bool receive(std::string &message)
    {
        char buffer[1024] = {0};
        int bytes = ::recv(sock, buffer, sizeof(buffer), 0);
        if (bytes <= 0)
        {
            return false;
        }

        // Decode payload (skipping headers for simplicity)
        message = std::string(buffer + 2, bytes - 2);
        return true;
    }
};

int main()
{
    WebSocketClient client("test.deribit.com", 443, "/ws/api/v2");
    if (!client.connect())
    {
        std::cerr << "Failed to connect to server\n";
        return 1;
    }

    std::cout << "Connected to server\n";

    std::string message = "Hello, WebSocket!";
    if (client.send(message))
    {
        std::cout << "Sent: " << message << "\n";
    }
    else
    {
        std::cerr << "Failed to send message\n";
    }

    std::string received;
    if (client.receive(received))
    {
        std::cout << "Received: " << received << "\n";
    }
    else
    {
        std::cerr << "Failed to receive message\n";
    }

    client.disconnect();
    return 0;
}
