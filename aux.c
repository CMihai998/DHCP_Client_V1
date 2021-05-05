//
// Created by mihai on 06.05.2021.
//

/*
	Simple udp client
*/
#include<stdio.h>	//printf
#include<string.h> //memset
#include<stdlib.h> //exit(0);
#include<arpa/inet.h>
#include<sys/socket.h>
#include <unistd.h>
#include <stdbool.h>



#define WG_INTERFACE_NAME "wg0"
#define WG_DUMMY_INTERFACE_NAME "wg_dummmy"
#define INTERNET_INTERFACE_NAME "eno1"

#define DHCP_PORT 6969

#define OLD_CONFIG_FILE "/etc/wireguard/wg0.conf"
#define NEW_CONFIG_FILE "/etc/wireguard/wg_dummmy.conf"

#define START_INTERFACE_COMMAND "wg-quick up wg0"
#define START_DUMMY_INTERFACE_COMMAND "wg-quick up wg_dummmy"
#define STOP_INTERFACE_COMMAND "wg-quick down wg_dummmy"

#define SERVER "192.168.3.15"
#define BUFLEN 512	//Max length of buffer
#define PORT 8888	//The port on which to send data

void die(char *s)
{
    perror(s);
    exit(1);
}
void error(char *message) {
    perror(message);
    exit(0);
}


struct Message {
    int OPTION;
    char PUBLIC_KEY[256];
    char ALLOWED_IPS[256];
    in_addr_t ADDRESS;
} MY_MESSAGE;



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


void send_message(int sock, struct sockaddr_in *server, int server_length) {
    if (sendto(sock, (struct Message*)&MY_MESSAGE, (1024 + (sizeof MY_MESSAGE)), 0, server, server_length) < 0) {
        error("sendto() - send_my_configuration - sending of configuration failed");
    }

    printf("Successfully sent: MY_CONFIGURATION (struct Configuration)"
           "\n\t\tOPTION (int) : %d"
           "\n\t\tPUBLIC_KEY (char[256]) : %s"
           "\n\t\tALLOWED_IPS (char[256] : %s"
           "\n\t\tADDRESS (in_addr_t) : %d",
           MY_MESSAGE.OPTION, MY_MESSAGE.PUBLIC_KEY, MY_MESSAGE.ALLOWED_IPS, MY_MESSAGE.ADDRESS);
}


void send_my_configuration(int sock, struct sockaddr_in *server, int server_length) {
    printf("Attempting to send MY_CONFIGURATION.....\n");
    MY_MESSAGE.OPTION = 0;
    MY_MESSAGE.ADDRESS = -1;
    send_message(sock, server, server_length);
}

struct in_addr * receive_address(int sock, struct sockaddr_in *server, int server_length) {
    int request = 1;
    printf("Initiating reception of an address...\n");

    struct in_addr *address = (struct in_addr*) malloc(sizeof (struct in_addr));

    printf("Receiving address...\n");
    if (recvfrom(sock, &address->s_addr, sizeof (in_addr_t), 0, (struct sockaddr*) server, &server_length) < 0)
        error("recvfrom() - receive_address -> address was not received");
    else
        printf("\tReceived: address: %d\n-----------------\n", address->s_addr);
    return address;
}
int main(void)
{
    struct sockaddr_in *si_other = (struct sockaddr_in*) malloc(sizeof (struct sockaddr_in));
    int s, i, slen=sizeof(struct sockaddr_in);
    char buf[BUFLEN];
    char message[BUFLEN];

    if ( (s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
        die("socket");
    }
    get_data_from_config_file();

    si_other->sin_family = AF_INET;
    si_other->sin_port = htons(PORT);

    if (inet_aton(SERVER , &si_other->sin_addr) == 0)
    {
        fprintf(stderr, "inet_aton() failed\n");
        exit(1);
    }
    send_my_configuration(s, si_other, slen);
    receive_address(s, si_other, slen);

    close(s);
    return 0;
}