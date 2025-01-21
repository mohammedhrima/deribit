#ifndef API_CLIENT_H
#define API_CLIENT_H

#include <string>
#include <map>

class APIClient {
public:
    APIClient(const std::string& apiKey, const std::string& apiSecret);

    std::string placeOrder(const std::string& symbol, double price, double amount, const std::string& side);
    std::string cancelOrder(const std::string& orderId);
    std::string modifyOrder(const std::string& orderId, double newPrice);
    std::string getOrderbook(const std::string& symbol);
    std::string getPositions();

private:
    std::string apiKey;
    std::string apiSecret;
    std::string token;

    std::string sendRequest(const std::string& endpoint, const std::string& postData);
    std::string getAuthToken(const std::string& apiKey, const std::string& apiSecret);
};

#endif