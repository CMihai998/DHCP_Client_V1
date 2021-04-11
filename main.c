#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>

#define DHCP_PORT 6969

void error(char *message) {
    perror(message);
    exit(0);
}

/**
 * Sends configuration to server
 * @param sock
 * @param server
 * @param server_length
 */
void send_configuration(int sock, struct sockaddr_in *server, int server_length) {
    int request = -1;
    printf("Initiating sending of configuration...\n");
    if (sendto(sock, &request, sizeof (int), 0, server, server_length) < 0)
        error("sendto() - send_configuration -> initialization of sending config\n");

    printf("Sending configuration...\n");
    struct in_addr *lower = (struct in_addr*) malloc(sizeof (struct in_addr));
    struct in_addr *upper = (struct in_addr*) malloc(sizeof (struct in_addr));
    lower->s_addr = 20;
    upper->s_addr = 1000;
    if (sendto(sock, &lower->s_addr, sizeof (in_addr_t), 0, server, server_length) < 0)
        error("sendto() - send_configuration -> send of lower bound address");
    else
        printf("\tSent: lower bound: %d\n", lower->s_addr);

    if (sendto(sock, &upper->s_addr, sizeof (in_addr_t), 0, server, server_length) < 0)
        error("sendto() - send_configuration -> send of upper bound address");
    else
        printf("\tSent: upper bound: %d\n-----------------\n", upper->s_addr);
}

/**
 * Requests and receives address from server
 * @param sock
 * @param server
 * @param server_length
 * @return
 */
struct in_addr * receive_address(int sock, struct sockaddr_in *server, int server_length) {
    int request = 1;
    printf("Initiating reception of an address...\n");
    if (sendto(sock, &request, sizeof (int), 0, server, server_length) < 0)
        error("sendto() - receive_address -> initialization of address receival\n");
    struct in_addr *address = (struct in_addr*) malloc(sizeof (struct in_addr));

    printf("Receiving address...\n");
    if (recvfrom(sock, &address->s_addr, sizeof (in_addr_t), 0, (struct sockaddr*) server, &server_length) < 0)
        error("recvfrom() - receive_address -> address was not received");
    else
        printf("\tReceived: address: %d\n-----------------\n", address->s_addr);
    return address;
}

/**
 * Signals server to shutdown
 * @param sock
 * @param server
 * @param server_length
 */
void shutdown_server(int sock, struct sockaddr_in *server, int server_length) {
    int request = 0;
    printf("Requesting server to shutdown...\n");
    if (sendto(sock, &request, sizeof (int), 0, server, server_length) < 0)
        error("sendto() - shutdown_server\n");
    else
        printf("\tServer shutdown.\n-----------------\n");

}

int main() {
    int sock, server_length, n;
    struct sockaddr_in *server = (struct sockaddr_in*) malloc(sizeof (struct sockaddr_in));

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        error("socket()");

    server->sin_family = AF_INET;
    server->sin_addr.s_addr = INADDR_ANY;
    server->sin_port = htons(DHCP_PORT);
    server_length = sizeof (struct sockaddr_in);

    send_configuration(sock, server, server_length);
    receive_address(sock, server, server_length);
    receive_address(sock, server, server_length);
    receive_address(sock, server, server_length);

    shutdown_server(sock, server, server_length);
    return 0;
}


