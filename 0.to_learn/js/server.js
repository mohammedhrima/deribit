const WebSocket = require('ws');
const CLIENT_ID = "6ljNdSET"
const CLIENT_SECRET = "R08jkZ_yC7yzHfrl1o0MXxIlSZwmJ-AaboLOJqcNCgM"

const ws = new WebSocket('wss://test.deribit.com/ws/api/v2');

const sendMessage = (message) => ws.send(JSON.stringify(message));

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

const order = {
  jsonrpc: "2.0",
  id: 2,
  method: "private/buy",
  params: {
    instrument_name: "BTC-PERPETUAL",
    amount: 10,
    price: 10,
    type: "limit",
  },
};

const order_id = "30808934318";

const cancel = {
  jsonrpc: "2.0",
  id: 3,
  method: "private/cancel",
  params: {
    order_id: order_id,
  },
}

const modify = {
  jsonrpc: "2.0",
  id: 4,
  method: "private/edit",
  params: {
    order_id: order_id,
    amount: 20,
    price: 20,
  },
};


// get_order_book?depth=5&instrument_name=BTC-PERPETUAL
const get_order_book = {
  jsonrpc: "2.0",
  id: 6,
  method: "public/get_order_book",
  params: {
    instrument_name: "BTC-PERPETUAL",
    depth: 5,
  },
};


const view = {
  jsonrpc: "2.0",
  id: 6,
  method: "private/get_positions",
  params: {
    currency: "BTC", // Replace with the currency of interest
  },
}

ws.onopen = () => {
  console.log('WebSocket connection opened.');

  console.log("authenticated");
  sendMessage(authMessage);

  // console.log("place order");
  // sendMessage(order);

  // console.log("cancel order")
  // sendMessage(cancel)

  // console.log("modify");
  // sendMessage(modify)

  console.log("get_order_book");
  sendMessage(get_order_book)


  // console.log("view");
  // sendMessage(view)
};

ws.onmessage = (event) => {
  console.log('Received from server:', event.data);

  try {
    const response = JSON.parse(event.data);
    if (response.error) {
      console.error('Error response from server:', response.error);
    } else if (response.result) {
      console.log('Successful response:', response.result);
    } else if (response.method && response.method === 'public/auth') {
      console.log('Authentication successful:', response);
    }
  }
  catch (error) { console.error('Failed to parse server message:', error.message); }
};


ws.onerror = (error) => {
  console.error('WebSocket error:', error.message);
};

ws.onclose = () => {
  console.log('WebSocket connection closed.');
};

