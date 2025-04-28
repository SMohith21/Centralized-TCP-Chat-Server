#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sstream>
#include <vector>
#include <sys/select.h>
#include <set>
#include "../include/logger.h"

#define BUFFER_SIZE 1024

int clientSocket = -1;  // Track client socket globally
std::string storedClientList = "";
std::set<std::string> blockedIPs;
void start_client(int port) {
    struct sockaddr_in serverAddr;
    std::string userInput;

    fd_set readfds;
    
    cse4589_print_and_log("Enter commands:");

    while (true) {
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        if (clientSocket != -1) FD_SET(clientSocket, &readfds);
        int max_fd = clientSocket > STDIN_FILENO ? clientSocket : STDIN_FILENO;

        select(max_fd + 1, &readfds, NULL, NULL, NULL);

        // Handle user input
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            std::getline(std::cin, userInput);

            if (userInput.substr(0, 6) == "LOGIN ") {
                if (clientSocket != -1) {
                    cse4589_print_and_log("[LOGIN:ERROR]\n");
                    cse4589_print_and_log("[LOGIN:END]\n");
                    continue;
                }

                std::istringstream iss(userInput.substr(6));
                std::string serverIp;
                int serverPort;
                iss >> serverIp >> serverPort;

                clientSocket = socket(AF_INET, SOCK_STREAM, 0);
                if (clientSocket < 0) {
                    perror("Socket creation failed");
                    cse4589_print_and_log("[LOGIN:ERROR]\n");
                    cse4589_print_and_log("[LOGIN:END]\n");
                    continue;
                }

                serverAddr.sin_family = AF_INET;
                serverAddr.sin_port = htons(serverPort);
                serverAddr.sin_addr.s_addr = inet_addr(serverIp.c_str());

                if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
                    perror("Connection failed");
                    close(clientSocket);
                    clientSocket = -1;
                    cse4589_print_and_log("[LOGIN:ERROR]\n");
                    cse4589_print_and_log("[LOGIN:END]\n");
                    continue;
                }

                std::string loginMessage = "LOGIN " + std::to_string(port);
                send(clientSocket, loginMessage.c_str(), loginMessage.size(), 0);

                // Process any buffered messages from the server for a short period
                fd_set tempfds;
                struct timeval tv;
                char tempBuffer[BUFFER_SIZE];
                while (true) {
                    FD_ZERO(&tempfds);
                    FD_SET(clientSocket, &tempfds);
                    tv.tv_sec = 1;
                    tv.tv_usec = 0;
                    int ret = select(clientSocket + 1, &tempfds, NULL, NULL, &tv);
                    if (ret > 0 && FD_ISSET(clientSocket, &tempfds)) {
                        int bytes = recv(clientSocket, tempBuffer, BUFFER_SIZE, 0);
                        if (bytes <= 0) break;
                        tempBuffer[bytes] = '\0';
                        std::string tempMsg(tempBuffer);
                        // If the message looks like a client list (e.g., starts with a digit), store it.
                        if (!tempMsg.empty() && isdigit(tempMsg[0])) {
                            storedClientList = tempMsg;
                        } else {
                            // Otherwise, treat it as a normal buffered message event.
                            cse4589_print_and_log("[RECEIVED:SUCCESS]\n");
                            cse4589_print_and_log("msg from:%s\n[msg]:%s\n", "Server", tempBuffer);
                            cse4589_print_and_log("[RECEIVED:END]\n");
                        }
                    } else {
                        break;
                    }
                }
                // After processing buffered messages, print the LOGIN success confirmation
                cse4589_print_and_log("[LOGIN:SUCCESS]\n");
                cse4589_print_and_log("[LOGIN:END]\n");
            } 

            else if (userInput == "REFRESH") {
                if (clientSocket == -1) {
                    cse4589_print_and_log("[REFRESH:ERROR]\n");
                    cse4589_print_and_log("[REFRESH:END]\n");
                    continue;
                }
                // Send REFRESH command to the server
                send(clientSocket, "REFRESH", 7, 0);
            
                // Buffer to receive updated client list
                char buffer[BUFFER_SIZE];
                int bytesRead = recv(clientSocket, buffer, BUFFER_SIZE, 0);
                if (bytesRead <= 0) {
                    cse4589_print_and_log("[REFRESH:ERROR]\n");
                    cse4589_print_and_log("[REFRESH:END]\n");
                } else {
                    buffer[bytesRead] = '\0';
                    // Update stored client list
                    storedClientList = std::string(buffer);
                    // Print the updated list
                    std::cout << "Updated Client List:\n" << storedClientList << std::endl;
                    cse4589_print_and_log("[REFRESH:SUCCESS]\n");
                    // Optionally, you can log the list as well if required:
                    // cse4589_print_and_log("%s\n", storedClientList.c_str());
                    cse4589_print_and_log("[REFRESH:END]\n");
                }
            }

            else if (userInput.substr(0, 5) == "SEND ") {
                if (clientSocket == -1) {
                    cse4589_print_and_log("[SEND:ERROR]\n");
                    cse4589_print_and_log("[SEND:END]\n");
                    continue;
                }
 
                std::istringstream iss(userInput.substr(5));
                std::string clientIp, message;
                if (!(iss >> clientIp) || !std::getline(iss >> std::ws, message) || message.empty()) {
                    cse4589_print_and_log("[SEND:ERROR]\n");
                    cse4589_print_and_log("[SEND:END]\n");
                    continue;
                }
 
                // Validate IP address format
                if (inet_addr(clientIp.c_str()) == INADDR_NONE) {
                    cse4589_print_and_log("[SEND:ERROR]\n");
                    cse4589_print_and_log("[SEND:END]\n");
                    continue;
                }
 
                // Check if the IP exists in the stored client list
                if (storedClientList.find(clientIp) == std::string::npos) {
                    cse4589_print_and_log("[SEND:ERROR]\n");
                    cse4589_print_and_log("[SEND:END]\n");
                    continue;
                }
 
                // Check if the message length exceeds 256 bytes
                if (message.size() > 256) {
                    cse4589_print_and_log("[SEND:ERROR]\n");
                    cse4589_print_and_log("[SEND:END]\n");
                    continue;
                }
 
                // Verify that the message consists of valid ASCII characters
                bool validASCII = true;
                for (char c : message) {
                    if ((unsigned char)c > 127) {
                        validASCII = false;
                        break;
                    }
                }
                if (!validASCII) {
                    cse4589_print_and_log("[SEND:ERROR]\n");
                    cse4589_print_and_log("[SEND:END]\n");
                    continue;
                }
 
                std::string fullMessage = "SEND " + clientIp + " " + message + "\n";
                send(clientSocket, fullMessage.c_str(), fullMessage.size(), 0);
                cse4589_print_and_log("[SEND:SUCCESS]\n");
                cse4589_print_and_log("[SEND:END]\n");
            }

            else if (userInput.substr(0, 10) == "BROADCAST ") {
                if (clientSocket == -1) {
                    cse4589_print_and_log("[BROADCAST:ERROR]\n");
                    cse4589_print_and_log("[BROADCAST:END]\n");
                    continue;
                }

                std::string message = userInput.substr(10);
                if (message.empty()) {
                    cse4589_print_and_log("[BROADCAST:ERROR]\n");
                    cse4589_print_and_log("[BROADCAST:END]\n");
                    continue;
                }

                std::string broadcastMessage = "BROADCAST " + message + "\n";
                send(clientSocket, broadcastMessage.c_str(), broadcastMessage.size(), 0);
                cse4589_print_and_log("[BROADCAST:SUCCESS]\n");
                cse4589_print_and_log("[BROADCAST:END]\n");
            } 
 
            else if (userInput.substr(0,6) == "BLOCK ") {
                if (clientSocket == -1) {
                    cse4589_print_and_log("[BLOCK:ERROR]\n");
                    cse4589_print_and_log("[BLOCK:END]\n");
                    continue;
                }
                std::string targetIP = userInput.substr(6);
                // Trim whitespace from the extracted IP
                size_t start = targetIP.find_first_not_of(" \t\n\r");
                if (start != std::string::npos) {
                    targetIP = targetIP.substr(start);
                } else {
                    targetIP = "";
                }
                if (targetIP.empty()) {
                    cse4589_print_and_log("[BLOCK:ERROR]\n");
                    cse4589_print_and_log("[BLOCK:END]\n");
                    continue;
                }
                // Validate IP format
                if (inet_addr(targetIP.c_str()) == INADDR_NONE) {
                    cse4589_print_and_log("[BLOCK:ERROR]\n");
                    cse4589_print_and_log("[BLOCK:END]\n");
                    continue;
                }
                // Check if targetIP exists in the stored client list
                if (storedClientList.find(targetIP) == std::string::npos) {
                    cse4589_print_and_log("[BLOCK:ERROR]\n");
                    cse4589_print_and_log("[BLOCK:END]\n");
                    continue;
                }
                // Check if the IP is already blocked
                if (blockedIPs.find(targetIP) != blockedIPs.end()) {
                    cse4589_print_and_log("[BLOCK:ERROR]\n");
                    cse4589_print_and_log("[BLOCK:END]\n");
                    continue;
                }
                // Add the IP to the blocked list
                blockedIPs.insert(targetIP);
                // Construct and send the BLOCK command to the server
                std::string blockCmd = "BLOCK " + targetIP + "\n";
                send(clientSocket, blockCmd.c_str(), blockCmd.size(), 0);
                cse4589_print_and_log("[BLOCK:SUCCESS]\n");
                cse4589_print_and_log("[BLOCK:END]\n");
            }
            else if (userInput.substr(0,8) == "UNBLOCK ") {
                if (clientSocket == -1) {
                    cse4589_print_and_log("[UNBLOCK:ERROR]\n");
                    cse4589_print_and_log("[UNBLOCK:END]\n");
                    continue;
                }
                std::string targetIP = userInput.substr(8);
                // Trim whitespace from the extracted IP
                size_t start = targetIP.find_first_not_of(" \t\n\r");
                if (start != std::string::npos) {
                    targetIP = targetIP.substr(start);
                } else {
                    targetIP = "";
                }
                if (targetIP.empty()) {
                    cse4589_print_and_log("[UNBLOCK:ERROR]\n");
                    cse4589_print_and_log("[UNBLOCK:END]\n");
                    continue;
                }
                // Validate IP format
                if (inet_addr(targetIP.c_str()) == INADDR_NONE) {
                    cse4589_print_and_log("[UNBLOCK:ERROR]\n");
                    cse4589_print_and_log("[UNBLOCK:END]\n");
                    continue;
                }
                // Check if targetIP exists in the stored client list
                if (storedClientList.find(targetIP) == std::string::npos) {
                    cse4589_print_and_log("[UNBLOCK:ERROR]\n");
                    cse4589_print_and_log("[UNBLOCK:END]\n");
                    continue;
                }
                // Check if the IP is actually blocked
                if (blockedIPs.find(targetIP) == blockedIPs.end()) {
                    cse4589_print_and_log("[UNBLOCK:ERROR]\n");
                    cse4589_print_and_log("[UNBLOCK:END]\n");
                    continue;
                }
                // Remove the IP from the blocked list
                blockedIPs.erase(targetIP);
                // Construct and send the UNBLOCK command to the server
                std::string unblockCmd = "UNBLOCK " + targetIP + "\n";
                send(clientSocket, unblockCmd.c_str(), unblockCmd.size(), 0);
                cse4589_print_and_log("[UNBLOCK:SUCCESS]\n");
                cse4589_print_and_log("[UNBLOCK:END]\n");
            }
            else if (userInput == "LIST") {
                if (storedClientList.empty()) {
                    cse4589_print_and_log("[LIST:ERROR]\n");
                    cse4589_print_and_log("[LIST:END]\n");
                } else {
                    std::cout << "Client List:\n" << storedClientList << std::endl;
                    cse4589_print_and_log("[LIST:SUCCESS]\n");
                    cse4589_print_and_log("[LIST:END]\n");
                }
            }
            else if (userInput == "LOGOUT") {
                if (clientSocket == -1) {
                    cse4589_print_and_log("[LOGOUT:ERROR]\n");
                    cse4589_print_and_log("[LOGOUT:END]\n");
                    continue;
                }
                // Send the LOGOUT command to the server
                send(clientSocket, "LOGOUT", 6, 0);
                close(clientSocket);
                clientSocket = -1;
                cse4589_print_and_log("[LOGOUT:SUCCESS]\n");
                cse4589_print_and_log("[LOGOUT:END]\n");
            }
            else if (userInput == "EXIT") {
                if (clientSocket != -1) {
                    send(clientSocket, "EXIT", 4, 0);
                    send(clientSocket, "LOGOUT", 6, 0);
                    close(clientSocket);
                }
                cse4589_print_and_log("[EXIT]\n");
                break;
            } 

            else if (userInput == "AUTHOR") {
                cse4589_print_and_log("[AUTHOR:SUCCESS]\n");
                cse4589_print_and_log("I, %s, have read and understood the course academic integrity policy.\n", "abishekt-savula");
                cse4589_print_and_log("[AUTHOR:END]\n");
            }
            else if (userInput == "IP") {
                int sock = socket(AF_INET, SOCK_DGRAM, 0);
                struct sockaddr_in serv;
                serv.sin_family = AF_INET;
                serv.sin_port = htons(80);
                serv.sin_addr.s_addr = inet_addr("8.8.8.8");
                connect(sock, (struct sockaddr*)&serv, sizeof(serv));
                struct sockaddr_in local;
                socklen_t len = sizeof(local);
                getsockname(sock, (struct sockaddr*)&local, &len);
                close(sock);
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &local.sin_addr, ip_str, sizeof(ip_str));
                cse4589_print_and_log("[IP:SUCCESS]\n");
                cse4589_print_and_log("IP:%s\n", ip_str);
                cse4589_print_and_log("[IP:END]\n");
            }
            else if (userInput == "PORT") {
                cse4589_print_and_log("[PORT:SUCCESS]\n");
                cse4589_print_and_log("PORT:%d\n", port);
                cse4589_print_and_log("[PORT:END]\n");
            }
            else {
                cse4589_print_and_log("[ERROR] Invalid command.\n");
            }
        }
        

        // Handle incoming messages from server
        if (clientSocket != -1 && FD_ISSET(clientSocket, &readfds)) {
            char buffer[BUFFER_SIZE];
            int bytesRead = recv(clientSocket, buffer, BUFFER_SIZE, 0);
            if (bytesRead <= 0) {
                cse4589_print_and_log("[SERVER DISCONNECTED]\n");
                close(clientSocket);
                clientSocket = -1;
            } else {
                buffer[bytesRead] = '\0';
                std::string received(buffer);
                std::string sender;
                std::string actualMessage;
                if (received.find("FROM:") == 0) {
                    size_t pos = received.find("\n");
                    if (pos != std::string::npos) {
                        sender = received.substr(5, pos - 5);
                        actualMessage = received.substr(pos + 1);
                    } else {
                        sender = "Unknown";
                        actualMessage = received;
                    }
                } else {
                    sender = "Server";
                    actualMessage = received;
                }
                cse4589_print_and_log("[RECEIVED:SUCCESS]\n");
                cse4589_print_and_log("msg from:%s\n[msg]:%s\n", sender.c_str(), actualMessage.c_str());
                cse4589_print_and_log("[RECEIVED:END]\n");
            }
        }
    }
}