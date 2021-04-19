#define _GNU_SOURCE     /* To get defns of NI_MAXSERV and NI_MAXHOST */
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_link.h>
#include <stdbool.h>
#include <string.h>
#include <sys/wait.h>
#include <fcntl.h>

#define WG_NAME "wg0"
#define DHCP_PORT 6969
#define OLD_CONFIG_FILE "/etc/wireguard/wg0.conf"
#define NEW_CONFIG_FILE "/etc/wireguard/wg1.conf"
#define START_INTERFACE_COMMAND "wg-quick up wg0"
#define STOP_INTERFACE_COMMAND "wg-quick down wg0"


char PUBLIC_KEY[256], ALLOWED_IPS[256];

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
 * Returns address to DHCP server
 * @param sock
 * @param server
 * @param server_length
 * @param address
 */
void return_address(int sock, struct sockaddr_in *server, int server_length, struct in_addr *address) {
    int request = 2;
    printf("Initiating address return...\n");
    if (sendto(sock, &request, sizeof (int), 0, server, server_length) < 0)
        error("sendto() - return_address -> initiating address return\n");

    if (sendto(sock, &address->s_addr, sizeof (in_addr_t), 0, server, server_length) < 0)
        error("sendto() - return_address -> failed to return address to server");
    else
        printf("\tSent: returned address: %d\n-----------------\n", address->s_addr);

    free(address);
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


void check_for_shutdown(int sock, struct sockaddr_in *server, int server_length) {
    struct ifaddrs *ifaddr;
    bool found;


    LOOP:

        found = false;
        if (getifaddrs(&ifaddr) == -1)
            error("getifaddrs() - check_for_shutdown()");

        for (struct ifaddrs *ifa = ifaddr; ifa != NULL && found == false;
             ifa = ifa->ifa_next) {

            if (ifa->ifa_addr == NULL)
                continue;

            if (strcmp(ifa->ifa_name, WG_NAME) == 0)
                found = true;
        }

        freeifaddrs(ifaddr);

        if (found == false) {
            return_address(sock, server, server_length, NULL);
            exit(EXIT_SUCCESS);
        }

        sleep(120);

    goto LOOP;

}

void start_interface() {
    system(START_INTERFACE_COMMAND);
}

void stop_interface() {
    system(STOP_INTERFACE_COMMAND);
}

void usage() {
    int sock, server_length, n;
    struct sockaddr_in *server = (struct sockaddr_in*) malloc(sizeof (struct sockaddr_in));

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        error("socket()");

    server->sin_family = AF_INET;
    server->sin_addr.s_addr = INADDR_ANY;
    server->sin_port = htons(DHCP_PORT);
    server_length = sizeof (struct sockaddr_in);

    struct in_addr* address = receive_address(sock, server, server_length);
    //setup wg0 with address
    //send allowed ips to server
    //send public key to server
    //spawn_check(sock, server, server_length_address)
    //check died, exit || return address and exit
}

void get_data_from_config_file() {
    bool public_key_found = false, allowed_ips_found = false;
    char line[512], *word_list[64], delimit[]=" ";
    FILE *fp;
    int i;
    fp = fopen(OLD_CONFIG_FILE, "r");

    if (fp == NULL)
        error("fopen() - CONFIG_FILE");

    while (fgets(line, 512, fp)) {
        i = 0;
        word_list[i] = strtok(line, delimit);
        while (word_list[i] != NULL)
            word_list[++i] = strtok(NULL, delimit);

        if (strcmp(word_list[0], "PublicKey") == 0) {
            strcpy(PUBLIC_KEY, word_list[2]);
            public_key_found = true;
        }
        if (strcmp(word_list[0], "AllowedIPs") == 0) {
            strcpy(ALLOWED_IPS, word_list[2]);
            allowed_ips_found = true;
        }

        if (public_key_found && allowed_ips_found) {
            fclose(fp);
            printf("\tPUBLIC_KEY = %s", PUBLIC_KEY);
            printf("\n\tALLOWED_IPS = %s", ALLOWED_IPS);
            return;
        }
    }

    close(fp);
    error("get_data_from_config_file() "
          "- INVALID CONFIG FILE! PublicKey AND AllowedIPs are mandatory");
}

void write_address_to_file(struct in_addr *address) {
    char new_content[262144], line[512], *word_list[64], delimit[]=" ";
    char *readable_address = inet_ntoa(*address);
    FILE *input_file, *new_file;
    bool address_written = false;
    int i;

    input_file = fopen(OLD_CONFIG_FILE, "r");
    if (input_file == NULL)
        error("fopen() - OLD_CONFIG_FILE");

    while (fgets(line, 512, input_file)) {
        i = 0;

        if (!address_written) {
            word_list[i] = strtok(line, delimit);
            while (word_list[i] != NULL) {
                if (i == 2 && strcmp("Address", word_list[0]) == 0) {
                    int length = strlen(new_content);
//                    strcpy(new_content[length - 1], " = ");
                    new_content[length - 1] = ' ';
                    new_content[length] = '=';
                    new_content[length + 1] = ' ';
                    new_content[length + 2] = '\0';
                    strcat(new_content, readable_address);
                    strcat(new_content, "\n");
                    address_written = true;
                } else {
                    strcat(new_content, word_list[i]);
                }
                word_list[++i] = strtok(NULL, delimit);
            }
        } else {
            strcat(new_content, line);
        }
    }
    close(input_file);
    printf("%s", new_content);

//    new_file = fopen(NEW_CONFIG_FILE, "w");
//    if (new_file == NULL)
//        error("fopen() - NEW_CONFIG_FILE");
//
//    fputs(new_content, new_file);
//    close(new_file);
}

int main() {
    char *address;
    struct in_addr *addr = (struct in_addr*) malloc(sizeof (struct in_addr));
    addr->s_addr = 1;
    write_address_to_file(addr);

    start_interface();
    stop_interface();
//    get_data_from_config_file();
    return 0;
}



void mmight_be_useful() {
    struct ifaddrs *ifaddr;
    int family, s;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    /* Walk through linked list, maintaining head pointer so we
       can free list later. */

    for (struct ifaddrs *ifa = ifaddr; ifa != NULL;
         ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        /* Display interface name and family (including symbolic
           form of the latter for the common families). */

        printf("%-8s %s (%d)\n",
               ifa->ifa_name,
               (family == AF_PACKET) ? "AF_PACKET" :
               (family == AF_INET) ? "AF_INET" :
               (family == AF_INET6) ? "AF_INET6" : "???",
               family);

        /* For an AF_INET* interface address, display the address. */

        if (family == AF_INET || family == AF_INET6) {
            s = getnameinfo(ifa->ifa_addr,
                            (family == AF_INET) ? sizeof(struct sockaddr_in) :
                            sizeof(struct sockaddr_in6),
                            host, NI_MAXHOST,
                            NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                exit(EXIT_FAILURE);
            }

            printf("\t\taddress: <%s>\n", host);

        } else if (family == AF_PACKET && ifa->ifa_data != NULL) {
            struct rtnl_link_stats *stats = ifa->ifa_data;

            printf("\t\ttx_packets = %10u; rx_packets = %10u\n"
                   "\t\ttx_bytes   = %10u; rx_bytes   = %10u\n",
                   stats->tx_packets, stats->rx_packets,
                   stats->tx_bytes, stats->rx_bytes);
        }
    }

    freeifaddrs(ifaddr);
    exit(EXIT_SUCCESS);
}

void might_be_useful_v2() {
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
    struct in_addr* a1 = receive_address(sock, server, server_length);
    struct in_addr* a2 = receive_address(sock, server, server_length);
    struct in_addr* a3 = receive_address(sock, server, server_length);

    return_address(sock, server, server_length, a2);

    shutdown_server(sock, server, server_length);
}
//TODO: You are currently getting the private key of the server, you should add you private key to the config file and use that one (HINT: put it in the interface part and just don't check it after it was changed once)