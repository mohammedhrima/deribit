const WebSocket = require('ws'); 

const CLIENT_ID = "6ljNdSET"
const CLIENT_SECRET = "R08jkZ_yC7yzHfrl1o0MXxIlSZwmJ-AaboLOJqcNCgM"


const ws = new WebSocket('wss://test.deribit.com/ws/api/v2');

const authMessage = {
  jsonrpc: "2.0",
  id: 1,
  method: "public/auth",
  params: {
    grant_type: "client_credentials",
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
  },
};

// Utility to send messages
const sendMessage = (message) => {
  ws.send(JSON.stringify(message));
};

// Handle incoming messages
ws.onmessage = (event) => {
  console.log('Received from server:', event.data);

  try {
    const response = JSON.parse(event.data);
    if (response.error) {
      console.error('Error response from server:', response.error);
    } else if (response.result) {
      console.log('Successful response:', response.result);
    }
  } catch (error) {
    console.error('Failed to parse server message:', error.message);
  }
};

// On WebSocket open, authenticate
ws.onopen = () => {
  console.log('WebSocket connection opened.');
  sendMessage(authMessage);
};

// Handle WebSocket errors
ws.onerror = (error) => {
  console.error('WebSocket error:', error.message);
};

// Handle WebSocket close
ws.onclose = () => {
  console.log('WebSocket connection closed.');
};

// Helper functions for the operations
const placeOrder = (instrument, amount, price, type = "limit") => {
  const message = {
    jsonrpc: "2.0",
    id: 2,
    method: "private/buy",
    params: {
      instrument_name: instrument,
      amount: amount,
      type: type,
      price: price, // Ignored for market orders
    },
  };
  sendMessage(message);
};

const cancelOrder = (orderId) => {
  const message = {
    jsonrpc: "2.0",
    id: 3,
    method: "private/cancel",
    params: {
      order_id: orderId,
    },
  };
  sendMessage(message);
};

const modifyOrder = (orderId, amount, price) => {
  const message = {
    jsonrpc: "2.0",
    id: 4,
    method: "private/edit",
    params: {
      order_id: orderId,
      amount: amount,
      price: price,
    },
  };
  sendMessage(message);
};

const getOrderBook = (instrument) => {
  const message = {
    jsonrpc: "2.0",
    id: 5,
    method: "public/get_order_book",
    params: {
      instrument_name: instrument,
    },
  };
  sendMessage(message);
};

const viewCurrentPositions = () => {
  const message = {
    jsonrpc: "2.0",
    id: 6,
    method: "private/get_positions",
    params: {
      currency: "BTC", // Replace with the currency of interest
    },
  };
  sendMessage(message);
};

// Example usage after successful authentication
ws.onmessage = (event) => {
  const response = JSON.parse(event.data);

  if (response.id === 1 && response.result && response.result.access_token) {
    console.log('Authenticated successfully.');

    // Examples of API usage
    placeOrder("BTC-PERPETUAL", 10, 25000); // Place a buy order
    // cancelOrder("your_order_id");        // Cancel an order
    // modifyOrder("your_order_id", 5, 26000); // Modify an order
    // getOrderBook("BTC-PERPETUAL");      // Get orderbook
    // viewCurrentPositions();            // View current positions
  } else if (response.result) {
    console.log('Operation result:', response.result);
  } else if (response.error) {
    console.error('Error:', response.error);
  }
};
