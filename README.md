# Centralized-TCP-Chat-Server
A lightweight, socket-based text messaging application enabling communication between multiple clients via a centralized server.
---

Originally developed as a class project for CSE 489/589, University at Buffalo, Spring 2025.

---

## How It Works

This project implements a peer-to-server text communication system over TCP sockets. A server maintains active client sessions, handles client registrations, buffers offline messages, and processes commands for messaging, blocking, and statistics reporting. Clients connect to the server, send messages to peers, broadcast messages to all clients, and manage their own blocking preferences. If a recipient is offline, messages are stored and delivered upon their next login. The server uses select() for handling multiple simultaneous client connections, ensuring efficient non-blocking I/O operations.

---

## Messaging Features

The system supports a range of essential communication features. Clients can log in and log out, retrieve the list of online clients, and refresh it as needed. Users can send direct messages to specific clients or broadcast messages to all connected clients. If the intended recipient is offline, the server stores the message and delivers it once the recipient logs back in. Clients also have the ability to block or unblock specific peers, preventing unwanted messages. The server maintains basic communication statistics and manages blocked lists. All communication operations are handled asynchronously and efficiently through the use of non-blocking socket management.

---


## How to Run

1. Compile the Code

    ```bash
    make
    ```

2. Run the Server

    ```bash
    ./assignment1 s <port>
    ```

    Example:

    ```bash
    ./assignment1 s 12345
    ```

3. Run the Client

    ```bash
    ./assignment1 c <port>
    ```

    Example:

    ```bash
    ./assignment1 c 12345
    ```

4. Basic Commands Available at Client Shell

    ```text
    AUTHOR : Displays authorship information.
    IP : Displays the local IP address.
    PORT : Displays the local port.
    LOGIN <server_ip> <server_port> : Connects to server.
    LIST : Lists currently online clients.
    REFRESH : Refreshes client list from server.
    SEND <client_ip> <message> : Sends a direct message.
    BROADCAST <message> : Sends a message to all clients.
    BLOCK <client_ip> : Blocks messages from a client.
    UNBLOCK <client_ip> : Unblocks a previously blocked client.
    BLOCKED <client_ip> : Lists clients blocked by a client.
    STATISTICS : Shows communication statistics.
    LOGOUT : Disconnects from server without exiting application.
    EXIT : Gracefully exits the client application.
    ```
---
## Code Architecture

The server (`assignment1` in server mode) initializes a TCP socket, binds to the specified port, and listens for incoming client connections. It uses `select()` to handle multiple clients and standard input simultaneously. The server manages a dynamic list of connected clients, including their socket descriptors, IP addresses, and ports. It buffers messages for offline clients and delivers them upon client login. It also processes and enforces server-specific commands like `STATISTICS`, `SEND`, `BROADCAST`, `BLOCK`, and `UNBLOCK`, while managing blocked lists to filter communication appropriately.

The client (`assignment1` in client mode) connects to the server over TCP and maintains the socket connection for interactive communication. It accepts user input commands from the terminal and sends corresponding requests to the server. The client displays incoming messages, notifications, and error messages to the user and locally manages blocked IPs to control which messages are accepted. It is designed to gracefully handle server disconnections and performs necessary resource cleanup on exit or reconnection.
