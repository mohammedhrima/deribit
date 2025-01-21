#include "header.hpp"

int createServer()
{
   sockaddr_in addr;
   int fd;

   fd = socket(AF_INET, SOCK_STREAM, 0);
   if (fd < 0)
      throw Error("socket failed");

   int option = 1;
   if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &option, sizeof(option)))
   {
      close(fd);
      throw Error("setsockopt failed");
   }

   addr.sin_family = AF_INET;
   addr.sin_addr.s_addr = INADDR_ANY;
   addr.sin_port = htons(PORT);

   if (bind(fd, (sockaddr *)&addr, sizeof(addr)) < 0)
   {
      close(fd);
      throw Error("bind failed");
   }
   if (listen(fd, MAX_CONNECTIONS) < 0)
   {
      close(fd);
      throw Error("listen failed");
   }
   std::cout << "server listenning on port " << PORT << std::endl;
   return fd;
}

std::string generateResponse(int status, std::string state, std::string message)
{
   return "HTTP/1.1 " + std::to_string(status) + " " + state + CRLF +
          "Content-Type: text/plain" + CRLF +
          "Content-Length: " + std::to_string(message.length()) + CRLF + CRLF +
          message;
}

void handleClient(int clientSocket)
{
   char buffer[BUFFER_SIZE + 1] = {0};
   recv(clientSocket, buffer, BUFFER_SIZE, 0);

   std::string request(buffer);
   std::cout << "Received request: " << request << std::endl;
   std::string response = generateResponse(200, "OK", "hello world");

   send(clientSocket, response.c_str(), response.size(), 0);
   if (request.find("GET /home ") != std::string::npos)
   {
   }
   else
   {
      // send(clientSocket, RESPONSE_404.c_str(), RESPONSE_404.size(), 0);
   }

   close(clientSocket);
}

const std::string RESET = "\033[0m";
const std::string BLUE = "\033[34m";
const std::string GREEN = "\033[32m";
const std::string YELLOW = "\033[33m";
const std::string RED = "\033[31m";
const std::string CYAN = "\033[36m";

void clearScreen()
{
   std::cout << "\033[2J\033[1;1H"; // Clear screen and move cursor to top-left
}

void displayMenu()
{
   std::cout << BLUE << "\n\tChoose an action:\n"
             << RESET;
   std::cout << CYAN << "\t[1] " << RESET << "Authenticate\n";
   std::cout << CYAN << "\t[2] " << RESET << "Place Order\n";
   std::cout << CYAN << "\t[3] " << RESET << "Cancel Order\n";
   std::cout << CYAN << "\t[4] " << RESET << "Modify Order\n";
   std::cout << CYAN << "\t[5] " << RESET << "Get Order Book\n";
   std::cout << CYAN << "\t[6] " << RESET << "Clear Screen\n";
   std::cout << RED << "\t[0] " << RESET << "Exit\n";
   std::cout << YELLOW << "\n\tEnter your choice: " << RESET;
}

int main()
{
   try
   {
      int server_fd = createServer();
      // while (true)
      // {
      //     sockaddr_in clientAddr;
      //     socklen_t clientSize = sizeof(clientAddr);

      //     int clientSocket = accept(server_fd, (struct sockaddr *)&clientAddr, &clientSize);
      //     if (clientSocket < 0)
      //     {
      //         std::cerr << "Connection failed.\n";
      //         continue;
      //     }

      //     std::thread(handleClient, clientSocket).detach();
      // }
      std::string input;
      while (true)
      {
         displayMenu();

         // Read user input
         if (std::getline(std::cin, input))
         {
            // Clear screen if option [6] is selected
            if (input == "6")
            {
               clearScreen();
               continue; // Skip to next iteration
            }

            // Print the input
            std::cout << GREEN << "\n\tYou entered: " << RESET << input << std::endl;

            // Handle actions based on user input
            if (input == "1")
            {
               std::cout << GREEN << "\tAuthenticating...\n"
                         << RESET;
            }
            else if (input == "2")
            {
               std::cout << GREEN << "\tPlacing Order...\n"
                         << RESET;
            }
            else if (input == "3")
            {
               std::cout << GREEN << "\tCancelling Order...\n"
                         << RESET;
            }
            else if (input == "4")
            {
               std::cout << GREEN << "\tModifying Order...\n"
                         << RESET;
            }
            else if (input == "5")
            {
               std::cout << GREEN << "\tFetching Order Book...\n"
                         << RESET;
            }
            else if (input == "0")
            {
               std::cout << RED << "\tExiting...\n"
                         << RESET;
               break;
            }
            else
            {
               std::cout << RED << "\tInvalid choice. Please try again.\n"
                         << RESET;
            }
         }
         else
         {
            // If input stream is closed, exit the loop
            std::cerr << RED << "\tInput stream closed. Exiting...\n"
                      << RESET;
            break;
         }
      }
   }
   catch (Error &error)
   {
      std::cerr << error.what() << std::endl;
   }
}