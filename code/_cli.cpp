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

#define PORT 5000
#define MAX_CONNECTIONS 10

#define BUFFERSIZE 4096
#define CLIENT_ID "6ljNdSET"
#define CLIENT_SECRET "R08jkZ_yC7yzHfrl1o0MXxIlSZwmJ-AaboLOJqcNCgM"
#define DERIBIT_URL "test.deribit.com"
#define DERIBIT_PATH "/ws/api/v2"
#define DERIBIT_PORT 443

typedef struct timeval timeval;
typedef struct hostent hostent;
typedef struct sockaddr_in sockaddr_in;


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

class Client
{
public:
   int fd;
   size_t port;
   SSL_CTX *ctx;
   SSL *ssl;
   std::string url;
   std::string path;

   Client(const std::string url_, const std::string path_, size_t port_) : url(url_), path(path_), port(port_)
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
   ~Client()
   {
   }
   void init_connection()
   {
      fd = socket(AF_INET, SOCK_STREAM, 0);
      if (fd < 0)
         disconnect("failed to created socket");

      timeval tv;
      tv.tv_sec = 5;
      tv.tv_usec = 0;
      if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)))
         disconnect("failed to set socket options");

      hostent *host = gethostbyname(url.c_str());
      if (!host)
         disconnect("failed to resolve host");

      sockaddr_in server_address;
      server_address.sin_family = AF_INET;
      server_address.sin_port = htons(port);
      memcpy(&server_address.sin_addr, host->h_addr_list[0], host->h_length);

      if (::connect(fd, (struct sockaddr *)&server_address, sizeof(server_address)) < 0)
         disconnect("Connection failed");
   }
   void setup_ssl()
   {
      ssl = SSL_new(ctx);
      SSL_set_fd(ssl, fd);
      SSL_set_tlsext_host_name(ssl, url.c_str());

      if (SSL_connect(ssl) <= 0)
         disconnect("SSL handshake failed");
      X509 *cert = SSL_get_peer_certificate(ssl);
      if (!cert)
         disconnect("Invalid certificate");
      X509_free(cert);
   }

   void handshake()
   {
      std::ostringstream request;
      request << "GET " << path << " HTTP/1.1\r\n"
              << "Host: " << url << "\r\n"
              << "Upgrade: websocket\r\n"
              << "Connection: Upgrade\r\n"
              << "Sec-WebSocket-Key: " << Random::key() << "\r\n"
              << "Sec-WebSocket-Version: 13\r\n\r\n";
      if (SSL_write(ssl, request.str().c_str(), request.str().size()) <= 0)
         disconnect("Failed to send WebSocket handshake");

      char response[BUFFERSIZE + 1] = {0};
      if (SSL_read(ssl, response, BUFFERSIZE) < 0)
         disconnect("Failed to read handshake response");

      if (std::string(response).find("101 Switching Protocols") == std::string::npos)
         disconnect("WebSocket upgrade failed");
   }

   void connect()
   {
      init_connection();
      setup_ssl();
      handshake();
      std::cout << "connected succefully" << std::endl;
   }

   void disconnect(const char *cause = NULL)
   {
      if (fd > 0)
      {
         close(fd);
         fd = -1;
      }
      if (cause)
         throw Error(cause);
      if (ctx)
      {
         SSL_CTX_free(ctx);
         EVP_cleanup();
      }
      if (ssl)
      {
         SSL_free(ssl);
         ssl = nullptr;
      }
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
   int receive(std::string &message)
   {
      uint8_t header[2];
      int bytes;
      if ((bytes = SSL_read(ssl, header, 2)) <= 0)
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

   void authenticate()
   {
      const char *client_id = CLIENT_ID;
      const char *client_secret = CLIENT_SECRET;
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
         disconnect("failed to authenticate");

      std::string response;
      if (receive(response))
         std::cout << "Authentication response: " << response << std::endl;
   }

   void place_order(const std::string &instrument, double amount, double price, const std::string &type = "limit")
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
              << amount << R"(, "type": ")" << type << R"(", "price": )" << price << R"( 
            }
    })";

      if (!sendMessage(message.str()))
         disconnect("failed to authenticate");
      std::string response;
      if (receive(response))
         std::cout << "Place order response: " << response << std::endl;
   }

   void cancel_order(const std::string &order_id)
   {
      std::ostringstream message;
      message << R"({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "private/cancel",
        "params": {
            "order_id": ")"
              << order_id << R"("
        }
    })";

      if (!sendMessage(message.str()))
         disconnect("failed to cancel order");

      std::string response;
      if (receive(response))
         std::cout << "Cancel order response: " << response << std::endl;
   }

   void modify_order(const std::string &order_id, double amount, double price)
   {
      std::ostringstream message;
      message << R"({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "private/edit",
        "params": {
            "order_id": ")"
              << order_id << R"(",
            "amount": )"
              << amount << R"(,
            "price": )"
              << price << R"(
        }
    })";

      if (!sendMessage(message.str()))
         disconnect("failed to modify order");

      std::string response;
      if (receive(response))
         std::cout << "Modify order response: " << response << std::endl;
   }

   void get_positions(const std::string &currency)
   {
      std::ostringstream message;
      message << R"({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "private/get_positions",
        "params": {
            "currency": ")"
              << currency << R"("
        }
    })";

      if (!sendMessage(message.str()))
         disconnect("failed to get positions");

      std::string response;
      if (receive(response))
         std::cout << "Get positions response: " << response << std::endl;
   }
};

class Display
{
public:
   static const std::string reset;
   static const std::string red;

   static void clear()
   {
      std::cout << "\033[2J\033[1;1H";
   }

   static void menu()
   {
      std::cout << "\n--- Menu ---" << std::endl;
      std::cout << "[1] Place Order" << std::endl;
      std::cout << "[2] Cancel Order" << std::endl;
      std::cout << "[3] Modify Order" << std::endl;
      std::cout << "[4] Get Positions" << std::endl;
      std::cout << "[5] Clear Display" << std::endl;
      std::cout << "[0] Exit" << std::endl;
      std::cout << "Enter your choice: ";
   }
};

const std::string Display::reset = "\033[0m";
const std::string Display::red = "\033[31m";

int main(void)
{
   try
   {
      Client client(DERIBIT_URL, DERIBIT_PATH, DERIBIT_PORT);

      client.connect();
      client.authenticate();
      // client.place_order("BTC-PERPETUAL", 10.0, 25000);
      std::string input;
      while (true)
      {
         Display::menu();
         if (std::getline(std::cin, input))
         {
            if (input == "5")
            {
               Display::clear();
               continue;
            }
            if (input == "1")
            {
               std::string instrument, type;
               double amount, price;
               std::cout << "\tEnter instrument name: ";
               std::getline(std::cin, instrument);
               std::cout << "\tEnter amount: ";
               std::cin >> amount;
               std::cout << "\tEnter price: ";
               std::cin >> price;
               std::cin.ignore();
               std::cout << "\tEnter type (default: limit): ";
               std::getline(std::cin, type);
               if (type.empty())
                  type = "limit";
               client.place_order(instrument, amount, price, type);
            }
            else if (input == "2")
            {
               std::string order_id;
               std::cout << "\tEnter order ID: ";
               std::getline(std::cin, order_id);
               client.cancel_order(order_id);
            }
            else if (input == "3")
            {
               std::string order_id;
               double amount, price;
               std::cout << "\tEnter order ID: ";
               std::getline(std::cin, order_id);
               std::cout << "\tEnter new amount: ";
               std::cin >> amount;
               std::cout << "\tEnter new price: ";
               std::cin >> price;
               std::cin.ignore();
               client.modify_order(order_id, amount, price);
            }
            else if (input == "4")
            {
               std::string currency;
               std::cout << "\tEnter currency: ";
               std::getline(std::cin, currency);
               client.get_positions(currency);
            }
            else if (input == "0")
            {
               std::cout << "\tExiting...";
               break;
            }
            else
            {
               std::cout << Display::red << "\tInvalid choice. Please try again." << Display::reset;
            }
         }
         else
         {
            std::cerr << Display::red << "\tInput stream closed. Exiting..." << Display::reset;
            break;
         }
      }
      std::cout << std::endl;
   }
   catch (Error &error)
   {
      std::cerr << "Error: " << error.what() << std::endl;
   }
}