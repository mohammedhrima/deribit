#include "../includes/APIClient.hpp"
#include <curl/curl.h>
#include <iostream>
#include <sstream>
#include <nlohmann/json.hpp>
#include <fstream>
#include <curl/curl.h>
#include <iostream>
#include <cstdio>
#include <netdb.h>
#include <arpa/inet.h>

// Callback function to capture response in a string
size_t writeCallback(void* contents, size_t size, size_t nmemb, void* userdata) {
    ((std::string*)userdata)->append((char*)contents, size * nmemb);
    return size * nmemb;
}
std::string APIClient::getAuthToken(const std::string& clientId, const std::string& clientSecret) {
    CURL* curl = curl_easy_init();
    if (!curl) throw std::runtime_error("Failed to initialize CURL.");

    std::string response;

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    // Deribit requires JSON-RPC 2.0 format
    std::string postData = "{"
        "\"jsonrpc\": \"2.0\","
        "\"id\": \"auth\","
        "\"method\": \"public/auth\","
        "\"params\": {"
            "\"client_id\": \"" + clientId + "\","
            "\"client_secret\": \"" + clientSecret + "\","
            "\"grant_type\": \"client_credentials\""
        "}"
    "}";


    curl_easy_setopt(curl, CURLOPT_URL, "https://test.deribit.com/api/v2");
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);

    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        std::string error = "CURL error: " + std::string(curl_easy_strerror(res));
        throw std::runtime_error(error);
    }

    try {

        nlohmann::json jsonResponse = nlohmann::json::parse(response);
        
        // Check for JSON-RPC error
        if (jsonResponse.contains("error")) {
            const auto& error = jsonResponse["error"];
            std::string errorMessage = error["message"].get<std::string>();
            int errorCode = error["code"].get<int>();
            throw std::runtime_error("API error (" + std::to_string(errorCode) + "): " + errorMessage);
        }
        
        // Check for successful result
        if (jsonResponse.contains("result") && 
            jsonResponse["result"].contains("access_token")) {
            return jsonResponse["result"]["access_token"];
        }
        
        throw std::runtime_error("Invalid response format: " + response);

    } catch (const nlohmann::json::parse_error& e) {
        throw std::runtime_error("Failed to parse JSON response: " + std::string(e.what()) + 
                               "\nResponse received: " + response);
    } catch (const nlohmann::json::type_error& e) {
        throw std::runtime_error("JSON type error: " + std::string(e.what()) + 
                               "\nResponse received: " + response);
    }
}

APIClient::APIClient(const std::string& apiKey, const std::string& apiSecret)
    : apiKey(apiKey), apiSecret(apiSecret) {
        this->token = getAuthToken(apiKey, apiSecret);
    }

size_t writeCallback2(void* contents, size_t size, size_t nmemb, void* userp) {
    auto* output = static_cast<std::string*>(userp);
    if (!output) {
        return 0; // Abort if output is null
    }
    size_t totalSize = size * nmemb;
    output->append(static_cast<char*>(contents), totalSize);
    return totalSize;
}

std::string APIClient::placeOrder(const std::string& symbol, double price, double amount, const std::string& side) {
    // Format amount to 8 decimal places for BTC
    std::stringstream stream;
    stream << std::fixed << std::setprecision(8) << amount;
    std::string formattedAmount = stream.str();

    // Create JSON-RPC request for placing order
    std::string postData = "{"
        "\"jsonrpc\": \"2.0\","
        "\"id\": \"place_order\","
        "\"method\": \"private/" + side + "\","
        "\"params\": {"
            "\"instrument_name\": \"" + symbol + "\","
            "\"amount\": " + formattedAmount + ","
            "\"type\": \"limit\","
            "\"price\": " + std::to_string(price) + ","
            "\"post_only\": true,"
            "\"time_in_force\": \"good_til_cancelled\""
        "}"
    "}";

    return sendRequest("private/" + side, postData);
}

std::string APIClient::getOrderbook(const std::string& symbol) {
    // Create JSON-RPC request for orderbook
    std::string postData = "{"
        "\"jsonrpc\": \"2.0\","
        "\"id\": \"get_orderbook\","
        "\"method\": \"public/get_order_book\","
        "\"params\": {"
            "\"instrument_name\": \"" + symbol + "\","
            "\"depth\": 5"
        "}"
    "}";

    return sendRequest("public/get_order_book", postData);
}

std::string APIClient::modifyOrder(const std::string& orderId, double newPrice) {
    // Create JSON-RPC request for modifying order
    std::string postData = "{"
        "\"jsonrpc\": \"2.0\","
        "\"id\": \"edit_order\","
        "\"method\": \"private/edit\","
        "\"params\": {"
            "\"order_id\": \"" + orderId + "\","
            "\"price\": " + std::to_string(newPrice) + ","
            "\"amount\": 10.0,"
            "\"post_only\": true"
        "}"
    "}";

    return sendRequest("private/edit", postData);
}

std::string APIClient::cancelOrder(const std::string& orderId) {
    // Create JSON-RPC request for canceling order
    std::string postData = "{"
        "\"jsonrpc\": \"2.0\","
        "\"id\": \"cancel_order\","
        "\"method\": \"private/cancel\","
        "\"params\": {"
            "\"order_id\": \"" + orderId + "\""
        "}"
    "}";

    return sendRequest("private/cancel", postData);
}

std::string APIClient::getPositions() {
    // Create JSON-RPC request for getting positions
    std::string postData = "{"
        "\"jsonrpc\": \"2.0\","
        "\"id\": \"get_positions\","
        "\"method\": \"private/get_positions\","
        "\"params\": {"
            "\"currency\": \"BTC\","
            "\"kind\": \"future\""
        "}"
    "}";

    return sendRequest("private/get_positions", postData);
}

std::string APIClient::sendRequest(const std::string& endpoint, const std::string& postData) {
    (void)endpoint;
    CURL* curl = curl_easy_init();
    if (!curl) {
        throw std::runtime_error("Failed to initialize CURL");
    }

    std::string response;
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    // Add authorization header if we have a token
    if (!token.empty()) {
        headers = curl_slist_append(headers, ("Authorization: Bearer " + token).c_str());
    }

    std::string url = "https://test.deribit.com/api/v2";
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback2);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        throw std::runtime_error("CURL error: " + std::string(curl_easy_strerror(res)));
    }

    return response;
}