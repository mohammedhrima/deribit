#include "../includes/WebSocketServer.hpp"
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

WebSocketServer::WebSocketServer() : running(false) {}

void WebSocketServer::start(int port) {
    running = true;

    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        throw std::runtime_error("Failed to create socket");
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        throw std::runtime_error("Bind failed");
    }

    listen(serverSocket, 5);

    std::cout << "WebSocket server started on port " << port << std::endl;

    while (running) {
        int clientSocket = accept(serverSocket, nullptr, nullptr);
        if (clientSocket >= 0) {
            clients[clientSocket] = std::thread(&WebSocketServer::handleClient, this, clientSocket);
            clients[clientSocket].detach();
        }
    }

    close(serverSocket);
}

void WebSocketServer::stop() {
    running = false;
}

void WebSocketServer::broadcast(const std::string& message) {
    for (const auto& [clientSocket, _] : clients) {
        send(clientSocket, message.c_str(), message.size(), 0);
    }
}

void WebSocketServer::handleClient(int clientSocket) {
    char buffer[1024] = {0};
    while (recv(clientSocket, buffer, sizeof(buffer), 0) > 0) {
        std::cout << "Received: " << buffer << std::endl;
    }

    close(clientSocket);
    clients.erase(clientSocket);
}
