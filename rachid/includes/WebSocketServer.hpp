#ifndef WEBSOCKET_SERVER_H
#define WEBSOCKET_SERVER_H

#include <string>
#include <unordered_map>
#include <vector>
#include <thread>

class WebSocketServer {
public:
    WebSocketServer();
    void start(int port);
    void stop();
    void broadcast(const std::string& message);

private:
    void handleClient(int clientSocket);

    std::unordered_map<int, std::thread> clients;
    bool running;
};

#endif
