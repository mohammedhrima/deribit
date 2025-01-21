#include <iostream>
#include "../includes/APIClient.hpp"
#include "../includes/WebSocketServer.hpp"
#include <nlohmann/json.hpp>
#include <thread>

void testAPIClient() {
    const std::string apiKey = "nenWXBnk";
    const std::string apiSecret = "vyil-uZceEhiJNcK6qj8cbyseiM7IcHnfea554DXdXY";

    APIClient apiClient(apiKey, apiSecret);

    try {
        // Place an order
        std::cout << "Placing order..." << std::endl;
        std::string placeOrderResponse = apiClient.placeOrder("BTC-PERPETUAL", 20000.0, 10.0, "buy");
        std::cout << "Place Order Response: " << placeOrderResponse << std::endl;

        // Parse the JSON response
        std::string orderId = "";
        try {
            nlohmann::json_abi_v3_11_2::json response = nlohmann::json_abi_v3_11_2::json::parse(placeOrderResponse);

            // Getting the order_id
            orderId = response["result"]["order"]["order_id"];
            std::cout << "Order ID: " << orderId << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "Error parsing JSON: " << e.what() << std::endl;
        }
       

        // Get the orderbook
        std::cout << "Getting orderbook..." << std::endl;
        std::string orderbookResponse = apiClient.getOrderbook("BTC-PERPETUAL");
        std::cout << "Orderbook: " << orderbookResponse << std::endl;

        // Get current positions
        std::cout << "Getting positions..." << std::endl;
        std::string positionsResponse = apiClient.getPositions();
        std::cout << "Positions: " << positionsResponse << std::endl;

        // Modify an order
        std::cout << "Modifying order..." << std::endl;
        std::string modifyOrderResponse = apiClient.modifyOrder(orderId, 20500.0);
        std::cout << "Modify Order Response: " << modifyOrderResponse << std::endl;

        // Cancel an order
        std::cout << "Cancelling order..." << std::endl;
        std::string cancelOrderResponse = apiClient.cancelOrder(orderId);
        std::cout << "Cancel Order Response: " << cancelOrderResponse << std::endl;
    } catch (const std::exception& ex) {
        std::cerr << "APIClient Error: " << ex.what() << std::endl;
    }
}

void testWebSocketServer() {
    WebSocketServer server;

    // Start WebSocket server in a separate thread
    std::thread serverThread([&]() {
        try {
            server.start(9000); // Port number for WebSocket server
        } catch (const std::exception& ex) {
            std::cerr << "WebSocket Server Error: " << ex.what() << std::endl;
        }
    });

    // Simulate broadcasting market data
    std::this_thread::sleep_for(std::chrono::seconds(5));
    std::cout << "Broadcasting market data..." << std::endl;
    server.broadcast("{\"symbol\": \"BTC-PERPETUAL\", \"price\": 20000.0, \"volume\": 100}");

    // Allow server to run for a while
    std::this_thread::sleep_for(std::chrono::seconds(10));

    // Stop the server
    std::cout << "Stopping WebSocket server..." << std::endl;
    server.stop();

    // Join the server thread
    if (serverThread.joinable()) {
        serverThread.join();
    }
}

int main() {
    std::cout << "Starting Deribit Trading System..." << std::endl;

    // Test API Client
    std::cout << "Testing API Client..." << std::endl;
    testAPIClient();

    // Test WebSocket Server
    std::cout << "\nTesting WebSocket Server..." << std::endl;
    testWebSocketServer();

    std::cout << "Deribit Trading System tests completed." << std::endl;
    return 0;
}
