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
#include<arpa/inet.h>

#define WG_INTERFACE_NAME "wg0"
#define WG_DUMMY_INTERFACE_NAME "wg_dummmy"
#define INTERNET_INTERFACE_NAME "eno1"

#define DHCP_PORT 8888
#define SERVER "192.168.3.15"

#define OLD_CONFIG_FILE "/etc/wireguard/wg0.conf"
#define NEW_CONFIG_FILE "/etc/wireguard/wg_dummmy.conf"

#define START_INTERFACE_COMMAND "wg-quick up wg0"
#define START_DUMMY_INTERFACE_COMMAND "wg-quick up wg_dummmy"
#define STOP_INTERFACE_COMMAND "wg-quick down wg_dummmy"
#define DELETE_OLD_CONFIG_FILE_COMMAND "sudo rm /etc/wireguard/wg_dummmy.conf"

struct Message {
    int OPTION;
    char PUBLIC_KEY[256];
    char ALLOWED_IPS[256];
    in_addr_t ADDRESS;
} MY_MESSAGE;

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

void send_message(int sock, struct sockaddr_in *server, int server_length) {
    if (sendto(sock, (struct Message*)&MY_MESSAGE, (1024 + (sizeof MY_MESSAGE)), 0, server, server_length) < 0) {
        error("sendto() - send_my_configuration - sending of configuration failed");
    }

    printf("Successfully sent: MY_CONFIGURATION (struct Configuration)"
           "\n\t\tOPTION (int) : %d"
           "\n\t\tPUBLIC_KEY (char[256]) : %s"
           "\n\t\tALLOWED_IPS (char[256] : %s"
           "\n\t\tADDRESS (in_addr_t) : %d\n",
           MY_MESSAGE.OPTION, MY_MESSAGE.PUBLIC_KEY, MY_MESSAGE.ALLOWED_IPS, MY_MESSAGE.ADDRESS);
}

void return_address_v2(int sock, struct sockaddr_in *server, int server_length, struct in_addr *address) {
    MY_MESSAGE.OPTION = 1;
    MY_MESSAGE.ADDRESS = address->s_addr;

    send_message(sock, server, server_length);

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

void send_my_address(int sock, struct sockaddr_in *server, int server_length) {
    struct ifaddrs *ifaddr;
    in_addr_t address;
    int request = 3;

    if (getifaddrs(&ifaddr) == -1)
        error("getifaddrs() - send_my_address()");

    for (struct ifaddrs* current = ifaddr; current != NULL; current = current->ifa_next) {
        if (current->ifa_addr == NULL)
            continue;

        if(strcmp(current->ifa_name, INTERNET_INTERFACE_NAME) == 0 && current->ifa_addr->sa_family == AF_INET) {
            address = ((struct sockaddr_in *)current->ifa_addr)->sin_addr.s_addr;
            goto FOR_END;
        }
    }
    FOR_END:
    freeifaddrs(ifaddr);
    printf("Initiatiting sending of real address...");
    if (sendto(sock, &request, sizeof (int), 0, server, server_length) < 0)
        error("sendto() - send_my_address -> initiating sending my address\n");

    if (sendto(sock, &address, sizeof (in_addr_t), 0, server, server_length) < 0)
        error("sendto() - send_my_address -> failed to return address to server");
    else
        printf("\tSent: my address: %d\n-----------------\n", address);
}


void start_interface(char *interface_name) {
    if (strcmp(interface_name, WG_INTERFACE_NAME) == 0) {
        system(START_INTERFACE_COMMAND);
        return;
    }

    system(START_DUMMY_INTERFACE_COMMAND);}

void stop_interface() {
    system(STOP_INTERFACE_COMMAND);
}


/**
 * Checks if wireguard interface is down and if so, stops the application
 * @param sock
 * @param server
 * @param server_length
 */
void check_for_shutdown(int sock, struct sockaddr_in *server, int server_length) {
    struct ifaddrs *ifaddr;
    bool found;


    LOOP:
        sleep(120);

        found = false;
        if (getifaddrs(&ifaddr) == -1)
            error("getifaddrs() - check_for_shutdown()");

        for (struct ifaddrs *current = ifaddr; current != NULL && found == false; current = current->ifa_next) {
            if (current->ifa_addr == NULL)
                continue;

            if (strcmp(current->ifa_name, WG_DUMMY_INTERFACE_NAME) == 0)
                found = true;
        }

        freeifaddrs(ifaddr);

        if (found == false) {
            return_address(sock, server, server_length, NULL);
            stop_interface();
            exit(EXIT_SUCCESS);
        }
    goto LOOP;
}

void generate_and_set_private_key(char *private_key) {
    char output[256], command[128] = "echo ";
    FILE *output_file;

    strcat(command, private_key);
    memmove(&command[49], &command[50], strlen(command) - 49);
    strcat(command, " | tee privatekey | wg pubkey");

    output_file = popen(command, "r");
    if (output_file == NULL)
        error("popen() - command not run properly");

    if (fgets(output, sizeof output, output_file) == NULL)
        error("fgets() - something went wrong with reading the output of the command");

    pclose(output_file);

    strcpy(MY_MESSAGE.PUBLIC_KEY, output);
}

/**
 * Gets the public key and the allowed ips from config file defined at the begging and stores them in global variables.
 * This function uses global variables because those values remain unchanged from the beggining until the end of the execution.
 */
void get_data_from_config_file() {
    bool private_key_found = false, allowed_ips_found = false;
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

        if (strcmp(word_list[0], "PrivateKey") == 0) {
            generate_and_set_private_key(word_list[2]);
            private_key_found = true;
        }
        if (strcmp(word_list[0], "AllowedIPs") == 0) {
            strcpy(MY_MESSAGE.ALLOWED_IPS, word_list[2]);
            allowed_ips_found = true;
        }

        if (private_key_found && allowed_ips_found) {
            fclose(fp);
            return;
        }
    }

    close(fp);
    error("get_data_from_config_file() "
          "- INVALID CONFIG FILE! PublicKey AND AllowedIPs are mandatory");
}

/**
 * Writes address to the config file as the address used inside the VPN
 * @param address
 */
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
                    if (strcmp("AutoConfigurable", word_list[0]) != 0)
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
    system(DELETE_OLD_CONFIG_FILE_COMMAND);
    new_file = fopen(NEW_CONFIG_FILE, "w");
    if (new_file == NULL)
        error("fopen() - NEW_CONFIG_FILE");

    fputs(new_content, new_file);
    close(new_file);
}


void send_my_configuration(int sock, struct sockaddr_in *server, int server_length) {
    printf("Attempting to send MY_CONFIGURATION.....\n");
    MY_MESSAGE.OPTION = 0;
    MY_MESSAGE.ADDRESS = -1;
    send_message(sock, server, server_length);
}

bool is_auto_configurable() {
    char line[512], *word_list[64], delimit[] = " ";
    FILE *config_file;
    int words_per_line;
    config_file = fopen(OLD_CONFIG_FILE, "r");

    if (config_file == NULL)
        error("fopen() - CONFIG_FILE");

    while (fgets (line, 512, config_file)) {
        words_per_line = 0;
        word_list[words_per_line] = strtok(line, delimit);
        while (word_list[words_per_line] != NULL)
            word_list[++words_per_line] = strtok(NULL, delimit);

        if (strcmp(word_list[0], "AutoConfigurable") == 0 && strcmp(word_list[2], "True\n") == 0) {
            fclose(config_file);
            return true;
        }
    }
    fclose(config_file);
    return false;
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

int run() {
    if (!is_auto_configurable()) {
        start_interface(WG_INTERFACE_NAME);
        goto END;
    }
    struct sockaddr_in *server = (struct sockaddr_in*) malloc(sizeof (struct sockaddr_in));
    int sock, server_length = sizeof (struct sockaddr_in);

    get_data_from_config_file();

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0)
        error("socket()");

    server->sin_family = AF_INET;
    server->sin_port = htons(DHCP_PORT);
    if (inet_aton(SERVER, &server->sin_addr) == 0)
        error("inet_aton - setting server address failed");

    send_my_configuration(sock, server, server_length);
    struct in_addr *my_address = receive_address(sock, server, server_length);
    write_address_to_file(my_address);
//TODO: MAYBE USE THIS SHIT?
//    send_my_address(sock, server, server_length);
//    send_configuration(sock, server, server_length);


    start_interface(WG_DUMMY_INTERFACE_NAME);

    check_for_shutdown(sock, server, server_length);

    END:
    return 0;
}


int main() {
//    int sock, server_length, n;
//    struct sockaddr_in *server = (struct sockaddr_in*) malloc(sizeof (struct sockaddr_in));
//
//    sock = socket(AF_INET, SOCK_DGRAM, 0);
//    if (sock < 0)
//        error("socket()");
//
//    server->sin_family = AF_INET;
//    server->sin_addr.s_addr = INADDR_ANY;
//    server->sin_port = htons(DHCP_PORT);
//    server_length = sizeof (struct sockaddr_in);
//    send_my_address(sock, server, server_length);
//    run();
    run();
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
