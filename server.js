const net = require("net");
const chalk = require("chalk"); // Libary for styling text in the terminal

let clients = [];
let clientCount = 0;
const colors = [
  chalk.green,
  chalk.blue,
  chalk.magenta,
  chalk.cyan,
  chalk.yellow,
  chalk.red,
  // chalk.white, // bad contrast
  // chalk.gray, // bad contrast
];

// Creating TCP server
const server = net.createServer((socket) => {
  clientCount++;
  const clientName = `Client ${clientCount}`;
  const clientColor = colors[(clientCount - 1) % colors.length];

  socket.clientName = clientName;
  socket.clientColor = clientColor;
  clients.push(socket);

  const connectMessage = `>> ${clientName} connected`;
  console.log(clientColor(connectMessage));

  clients.forEach((client) => {
    client.write(clientColor(`${connectMessage}`));
  });

  // Handles data received from a client
  socket.on("data", (data) => {
    const message = data.toString().trim();

    if (message.length === 0) {
      return;
    }

    const formattedMessage = `${clientName}: ${message}`;
    console.log(clientColor(formattedMessage));

    // Broadcasts the message to all clients except who sent
    clients.forEach((client) => {
      if (client !== socket) {
        client.write(clientColor(`${formattedMessage}`));
      }
    });
  });

  // Handles client disconnection
  socket.on("end", () => {
    const disconnectMessage = `>> ${clientName} disconnected`;
    console.log(clientColor(disconnectMessage));

    // Removes client from list of clients
    clients = clients.filter((client) => client !== socket);

    // Sends disconnection message to all clients
    clients.forEach((client) => {
      client.write(clientColor(`${disconnectMessage}`));
    });
  });

  // Handles connection errors
  socket.on("error", (err) => {
    console.error(clientColor(`Error in ${clientName}:`), err.message);
  });
});

const PORT = 3000;

server.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
