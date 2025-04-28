#include <iostream>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <map>
#include <algorithm>
#include <netdb.h>
#include "../include/logger.h"
#include <sstream> // for istringstream

// Utility function to trim whitespace
std::string trim(const std::string &s) {
    size_t start = s.find_first_not_of(" \t\n\r");
    if (start == std::string::npos)
        return "";
    size_t end = s.find_last_not_of(" \t\n\r");
    return s.substr(start, end - start + 1);
}

#define MAX_CLIENTS 5
#define BUFFER_SIZE 1024

int serverPort;  

struct ClientInfo {
    int socket;
    std::string ip;
    int port;
    bool loggedIn;
    int messagesSent;
    int messagesReceived;
    std::vector<std::string> blockedIPs; // stores IPs this client has blocked
};

std::vector<ClientInfo> clients;
std::map<std::string, std::vector<std::string>> offlineMessages;

void broadcastMessage(const std::string& message, int senderSocket) {
    std::string senderIP = "Unknown";
    for (const auto &client : clients) {
        if (client.socket == senderSocket) {
            senderIP = client.ip;
            break;
        }
    }
    std::string relayedMessage = "FROM:" + senderIP + "\n" + message;
    for (auto &client : clients) {
        if (client.socket != senderSocket && client.socket != -1 && client.loggedIn) {
            bool blockedByRecipient = false;
            for (const auto &bip : client.blockedIPs) {
                if (bip == senderIP) {
                    blockedByRecipient = true;
                    break;
                }
            }
            if (!blockedByRecipient) {
                send(client.socket, relayedMessage.c_str(), relayedMessage.size(), 0);
            }
        }
    }
}

// Remove client from active connections (but keep info for STATISTICS)
void removeClient(int clientSocket) {
    auto it = std::find_if(clients.begin(), clients.end(),
                           [clientSocket](const ClientInfo& c) { return c.socket == clientSocket; });
    if (it != clients.end()) {
        it->loggedIn = false;
        close(it->socket);
        it->socket = -1; // mark as invalid
    }
}

// Main server function using select() to handle both network and shell commands
void start_server(int port) {
    int serverSocket, clientSocket;
    struct sockaddr_in serverAddr, clientAddr;
    socklen_t addrLen = sizeof(clientAddr);
    fd_set readfds;

    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        perror("Socket creation failed");
        return;
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);
    serverPort = port;

    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("Bind failed");
        return;
    }

    if (listen(serverSocket, MAX_CLIENTS) < 0) {
        perror("Listen failed");
        return;
    }

    std::cout << "Server listening on port " << port << std::endl;

    while (true) {
        FD_ZERO(&readfds);
        FD_SET(serverSocket, &readfds);
        int max_sd = serverSocket;

        // Add each active client socket to the set
        for (const auto &client : clients) {
            if (client.socket != -1) {
                FD_SET(client.socket, &readfds);
                if (client.socket > max_sd)
                    max_sd = client.socket;
            }
        }

        // Add STDIN (fd 0) to the set for shell commands
        FD_SET(0, &readfds);
        if (0 > max_sd)
            max_sd = 0;

        if (select(max_sd + 1, &readfds, NULL, NULL, NULL) < 0) {
            perror("Select error");
            continue;
        }

        // Accept new client connection
        if (FD_ISSET(serverSocket, &readfds)) {
            clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &addrLen);
            if (clientSocket < 0) {
                perror("Accept failed");
            } else {
                std::string clientIP = inet_ntoa(clientAddr.sin_addr);
        int clientPort = ntohs(clientAddr.sin_port);
        bool found = false;
        for (auto &client : clients) {
            if (client.ip == clientIP) {
                // Update the existing record
                client.socket = clientSocket;
                client.loggedIn = true;
                // Optionally, you may choose to reset or preserve message counts
                found = true;
                break;
            }
        }
        if (!found) {
                clients.push_back({clientSocket, clientIP, clientPort, true, 0, 0, {}});
        }
                std::cout << "New connection: " << clientIP << ":" << clientPort << std::endl;

                if (offlineMessages.find(clientIP) != offlineMessages.end()) {
                    for (auto &msg : offlineMessages[clientIP]) {
                        send(clientSocket, msg.c_str(), msg.size(), 0);
                        cse4589_print_and_log("[RECEIVED:SUCCESS]\n");
                        cse4589_print_and_log("msg from:%s\n[msg]:%s\n", "OfflineBuffer", msg.c_str());
                        cse4589_print_and_log("[RECEIVED:END]\n");
                    }
                    offlineMessages.erase(clientIP);
                }
            
            // Now, send the client list to the newly connected client
        {
            std::vector<ClientInfo> loggedInClients;
            for (const auto &client : clients) {
                if (client.loggedIn) {
                    loggedInClients.push_back(client);
                }
            }
            std::sort(loggedInClients.begin(), loggedInClients.end(),
                      [](const ClientInfo &a, const ClientInfo &b) { return a.port < b.port; });
            int list_id = 1;
            std::string clientList;
            for (const auto &client : loggedInClients) {
                struct sockaddr_in sa;
                char hostname[NI_MAXHOST];
                memset(&sa, 0, sizeof(sa));
                sa.sin_family = AF_INET;
                inet_pton(AF_INET, client.ip.c_str(), &(sa.sin_addr));
                getnameinfo((struct sockaddr*)&sa, sizeof(sa), hostname, NI_MAXHOST, NULL, 0, NI_NAMEREQD);
                char line[200];
                sprintf(line, "%-5d%-35s%-20s%-8d\n", list_id++, hostname, client.ip.c_str(), client.port);
                clientList += line;
            }
            // Send the client list to the new client.
            send(clientSocket, clientList.c_str(), clientList.size(), 0);
        }
    }
}


        // Process activity on client sockets
        for (auto it = clients.begin(); it != clients.end(); ) {
            if (it->socket == -1) {
                ++it;
                continue;
            }
            if (FD_ISSET(it->socket, &readfds)) {
                char buffer[BUFFER_SIZE];
                int bytesRead = recv(it->socket, buffer, BUFFER_SIZE, 0);
                if (bytesRead <= 0) {
                    std::cout << "Client disconnected: " << it->ip << ":" << it->port << std::endl;
                    removeClient(it->socket);
                    ++it; // Keep entry for statistics
                    continue;
                } else {
                    buffer[bytesRead] = '\0';
                    std::string rawMessage(buffer);
                    rawMessage = trim(rawMessage);

                    // Handle REFRESH command from client
                    if (rawMessage == "REFRESH") {
                        std::vector<ClientInfo> loggedInClients;
                        for (const auto &client : clients) {
                            if (client.loggedIn) {
                                loggedInClients.push_back(client);
                            }
                        }
                        std::sort(loggedInClients.begin(), loggedInClients.end(),
                                  [](const ClientInfo &a, const ClientInfo &b) { return a.port < b.port; });
                        int list_id = 1;
                        std::string clientList;
                        for (const auto &client : loggedInClients) {
                            struct sockaddr_in sa;
                            char hostname[NI_MAXHOST];
                            memset(&sa, 0, sizeof(sa));
                            sa.sin_family = AF_INET;
                            inet_pton(AF_INET, client.ip.c_str(), &(sa.sin_addr));
                            getnameinfo((struct sockaddr*)&sa, sizeof(sa), hostname, NI_MAXHOST, NULL, 0, NI_NAMEREQD);
                            char line[200];
                            sprintf(line, "%-5d%-35s%-20s%-8d\n", list_id++, hostname, client.ip.c_str(), client.port);
                            clientList += line;
                        }
                        send(it->socket, clientList.c_str(), clientList.size(), 0);
                        ++it;
                        continue;
                    } else if (rawMessage == "LOGOUT") {
                        removeClient(it->socket);
                        ++it;
                        continue;
                    } else if (rawMessage.find("BLOCK ") == 0) {
                        std::istringstream iss(rawMessage);
                        std::string command, targetIP;
                        iss >> command >> targetIP;
                        if (targetIP.empty()) {
                            std::cout << "Invalid BLOCK command (missing target IP): " << rawMessage << std::endl;
                            ++it;
                            continue;
                        } else {
                            auto& blkList = it->blockedIPs;
                            if (std::find(blkList.begin(), blkList.end(), targetIP) == blkList.end()) {
                                blkList.push_back(targetIP);
                            }
                            cse4589_print_and_log("[BLOCKED:SUCCESS]\n");
                            cse4589_print_and_log("[BLOCKED:END]\n");
                            ++it;
                            continue;
                        }
                    } else if (rawMessage.find("UNBLOCK ") == 0) {
                        std::istringstream iss(rawMessage);
                        std::string command, targetIP;
                        iss >> command >> targetIP;
                        if (targetIP.empty()) {
                            std::cout << "Invalid UNBLOCK command (missing target IP): " << rawMessage << std::endl;
                            ++it;
                            continue;
                        } else {
                            auto& blkList = it->blockedIPs;
                            blkList.erase(std::remove(blkList.begin(), blkList.end(), targetIP), blkList.end());
                            cse4589_print_and_log("[UNBLOCK:SUCCESS]\n");
                            cse4589_print_and_log("[UNBLOCK:END]\n");
                            ++it;
                            continue;
                        }
                    }

                    // Process message commands: SEND and BROADCAST
                    std::string messageToSend;
                    std::string targetIP = "255.255.255.255"; // Default for broadcast

                    if (rawMessage.find("SEND ") == 0) {
                        std::istringstream iss(rawMessage);
                        std::string command;
                        iss >> command; // should be "SEND"
                        if (!(iss >> targetIP)) {
                            std::cout << "Invalid SEND command (missing target IP): " << rawMessage << std::endl;
                            ++it;
                            continue;
                        }
                        std::getline(iss, messageToSend);
                        messageToSend = trim(messageToSend);
                        if (messageToSend.empty()) {
                            std::cout << "Empty message in SEND command." << std::endl;
                            ++it;
                            continue;
                        }
                    } else if (rawMessage.find("BROADCAST ") == 0) {
                        messageToSend = trim(rawMessage.substr(10));
                    } else {
                        messageToSend = rawMessage;
                    }

                    std::cout << "Received: " << messageToSend << std::endl;
                    it->messagesReceived++;

                    cse4589_print_and_log("[RELAYED:SUCCESS]\n");
                    cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", it->ip.c_str(), targetIP.c_str(), messageToSend.c_str());
                    cse4589_print_and_log("[RELAYED:END]\n");

                    std::string senderIP = it->ip;
                    std::string relayedMessage = "FROM:" + senderIP + "\n" + messageToSend;

                    if (targetIP == "255.255.255.255") {
                        // For broadcast, iterate over all clients (except sender)
                        for (auto &client : clients) {
                            if (client.socket != it->socket && client.socket != -1 && client.loggedIn) {
                                bool blockedByRecipient = false;
                                for (const auto &bip : client.blockedIPs) {
                                    if (bip == senderIP) {
                                        blockedByRecipient = true;
                                        break;
                                    }
                                }
                                if (!blockedByRecipient) {
                                    send(client.socket, relayedMessage.c_str(), relayedMessage.size(), 0);
                                }
                            }
                        }
                    } else {
                        // For unicast, send only to the intended recipient if not blocked
                        for (auto &client : clients) {
                            if (client.ip == targetIP) {
                                bool blockedByRecipient = false;
                                for (const auto &bip : client.blockedIPs) {
                                    if (bip == senderIP) {
                                        blockedByRecipient = true;
                                        break;
                                    }
                                }
                                if (!blockedByRecipient) {
                                        if (client.socket != -1 && client.loggedIn) {
                                            send(client.socket, relayedMessage.c_str(), relayedMessage.size(), 0);
                                        } else {
                                            offlineMessages[client.ip].push_back(relayedMessage);
                                        }
                                }
                            }
                        }
                    }
                    ++it;
                }
            } else {
                ++it;
            }
        } // End processing client sockets

        // Inline handling of shell commands from STDIN
        if (FD_ISSET(0, &readfds)) {
            std::string command;
            std::getline(std::cin, command);
            if (command == "AUTHOR") {
                cse4589_print_and_log("[AUTHOR:SUCCESS]\n");
                cse4589_print_and_log("I, %s, have read and understood the course academic integrity policy.\n", "abishekt-savula4");
                cse4589_print_and_log("[AUTHOR:END]\n");
            } else if (command == "IP") {
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
            } else if (command == "PORT") {
                cse4589_print_and_log("[PORT:SUCCESS]\n");
                cse4589_print_and_log("PORT:%d\n", serverPort);
                cse4589_print_and_log("[PORT:END]\n");
            } else if (command == "LIST") {
                cse4589_print_and_log("[LIST:SUCCESS]\n");
                std::vector<ClientInfo> loggedInClients;
                for (const auto &client : clients) {
                    if (client.loggedIn) {
                        loggedInClients.push_back(client);
                    }
                }
                std::sort(loggedInClients.begin(), loggedInClients.end(),
                          [](const ClientInfo &a, const ClientInfo &b) { return a.port < b.port; });
                int list_id = 1;
                for (const auto &client : loggedInClients) {
                    struct sockaddr_in sa;
                    char hostname[NI_MAXHOST];
                    memset(&sa, 0, sizeof(sa));
                    sa.sin_family = AF_INET;
                    inet_pton(AF_INET, client.ip.c_str(), &(sa.sin_addr));
                    getnameinfo((struct sockaddr*)&sa, sizeof(sa), hostname, NI_MAXHOST, NULL, 0, NI_NAMEREQD);
                    cse4589_print_and_log("%-5d%-35s%-20s%-8d\n", list_id++, hostname, client.ip.c_str(), client.port);
                }
                cse4589_print_and_log("[LIST:END]\n");
            } else if (command == "STATISTICS") {
                cse4589_print_and_log("[STATISTICS:SUCCESS]\n");
                std::vector<ClientInfo> allClients = clients;
                std::sort(allClients.begin(), allClients.end(),
                          [](const ClientInfo &a, const ClientInfo &b) { return a.port < b.port; });
                int list_id = 1;
                for (const auto &client : allClients) {
                    struct sockaddr_in sa;
                    char hostname[NI_MAXHOST];
                    memset(&sa, 0, sizeof(sa));
                    sa.sin_family = AF_INET;
                    inet_pton(AF_INET, client.ip.c_str(), &(sa.sin_addr));
                    getnameinfo((struct sockaddr*)&sa, sizeof(sa), hostname, NI_MAXHOST, NULL, 0, NI_NAMEREQD);
                    const char* status = client.loggedIn ? "logged-in" : "logged-out";
                    cse4589_print_and_log("%-5d%-35s%-8d%-8d%-8s\n",
                                          list_id++, hostname, client.messagesSent, client.messagesReceived, status);
                }
                cse4589_print_and_log("[STATISTICS:END]\n");
            } else if (command.find("BLOCKED") == 0) {
                // Expecting command format: "BLOCKED <client-ip>"
                std::istringstream iss(command);
                std::string cmd, clientIP;
                iss >> cmd >> clientIP;
                if (clientIP.empty()) {
                    cse4589_print_and_log("[BLOCKED:ERROR]\n");
                    cse4589_print_and_log("[BLOCKED:END]\n");
                } else {
                    bool found = false;
                    for (const auto &client : clients) {
                        if (client.ip == clientIP) {
                            found = true;
                            cse4589_print_and_log("[BLOCKED:SUCCESS]\n");
                            int list_id = 1;
                            for (const auto &bip : client.blockedIPs) {
                                struct sockaddr_in sa;
                                char hostname[NI_MAXHOST];
                                memset(&sa, 0, sizeof(sa));
                                sa.sin_family = AF_INET;
                                inet_pton(AF_INET, bip.c_str(), &(sa.sin_addr));
                                getnameinfo((struct sockaddr*)&sa, sizeof(sa), hostname, NI_MAXHOST, NULL, 0, NI_NAMEREQD);
                                cse4589_print_and_log("%-5d%-35s%-20s\n", list_id++, hostname, bip.c_str());
                            }
                            cse4589_print_and_log("[BLOCKED:END]\n");
                            break;
                        }
                    }
                    if (!found) {
                        cse4589_print_and_log("[BLOCKED:ERROR]\n");
                        cse4589_print_and_log("[BLOCKED:END]\n");
                    }
                }
            }
        } // End inline shell command handling

    } // End while(true)

    close(serverSocket);
} // End start_server functio
