const WebSocket = require('ws');
const CLIENT_ID = "6ljNdSET"
const CLIENT_SECRET = "R08jkZ_yC7yzHfrl1o0MXxIlSZwmJ-AaboLOJqcNCgM"

const ws = new WebSocket('wss://test.deribit.com/ws/api/v2');

const sendMessage = (message) => ws.send(JSON.stringify(message));


// main
ws.onopen = () => {
  console.log('WebSocket connection opened.');
  // authenticate
  sendMessage({
    jsonrpc: "2.0",
    id: 1,
    method: "public/auth",
    params: {
      grant_type: "client_credentials",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    },
  });
};

ws.onmessage = (event) => {
  console.log('Received from server:', event.data);

  try {
    const response = JSON.parse(event.data);
    if (response.error) console.error('Error response from server:', response.error);
    else if (response.result) console.log('Successful response:', response.result);
  }
  catch (error) { console.error('Failed to parse server message:', error.message); }
};

ws.onerror = (error) => {
  console.error('WebSocket error:', error.message);
};

ws.onclose = () => {
  console.log('WebSocket connection closed.');
};
