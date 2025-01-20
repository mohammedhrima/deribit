#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <cstring>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

const int PORT = 8080; // Port to listen on
const std::string RESPONSE_200 =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 13\r\n"
    "Connection: close\r\n\r\n"
    "Hello, Home!";

const std::string RESPONSE_404 =
    "HTTP/1.1 404 Not Found\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 9\r\n"
    "Connection: close\r\n\r\n"
    "Not Found";

// Function to handle each client connection
void handleClient(int clientSocket)
{
  char buffer[1024] = {0};
  read(clientSocket, buffer, sizeof(buffer) - 1);

  std::string request(buffer);
  std::cout << "Received request:\n"
            << request << std::endl;

  // Check if the request is for /home
  if (request.find("GET /home ") != std::string::npos)
  {
    send(clientSocket, RESPONSE_200.c_str(), RESPONSE_200.size(), 0);
  }
  else
  {
    send(clientSocket, RESPONSE_404.c_str(), RESPONSE_404.size(), 0);
  }

  close(clientSocket);
}

int main()
{
  int serverSocket;
  struct sockaddr_in serverAddr;

  // Create the socket
  serverSocket = socket(AF_INET, SOCK_STREAM, 0);
  if (serverSocket < 0)
  {
    std::cerr << "Socket creation failed.\n";
    return -1;
  }

  // Configure server address
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_addr.s_addr = INADDR_ANY;
  serverAddr.sin_port = htons(PORT);

  // Bind the socket
  if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
  {
    std::cerr << "Binding failed.\n";
    close(serverSocket);
    return -1;
  }

  // Listen for incoming connections
  if (listen(serverSocket, 10) < 0)
  {
    std::cerr << "Listening failed.\n";
    close(serverSocket);
    return -1;
  }

  std::cout << "Server listening on port " << PORT << "...\n";

  // Accept and handle connections
  while (true)
  {
    struct sockaddr_in clientAddr;
    socklen_t clientLen = sizeof(clientAddr);

    int clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddr, &clientLen);
    if (clientSocket < 0)
    {
      std::cerr << "Connection failed.\n";
      continue;
    }

    // Handle the client in a new thread
    std::thread(handleClient, clientSocket).detach();
  }

  close(serverSocket);
  return 0;
}
