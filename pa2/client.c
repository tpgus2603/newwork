#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>

#define SERVER_PORT 8080
#define TIMEOUT_SEC 10
#define MAXSIZE 1024
#define MAXMSIZE (2 + MAXSIZE) // 2 bytes for sequence number

void error_exit(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

uint16_t cal_seq(uint16_t prev_seq, const char *prev_input) {
    return prev_seq + strlen(prev_input);
}

int main() {
    int sockfd;
    struct sockaddr_in server_addr;
    socklen_t addr_len = sizeof(server_addr);
    char input_str[MAXSIZE];
    char message[MAXMSIZE];
    char recv_buffer[MAXMSIZE];
    uint16_t seq_num = 0;
    ssize_t num_bytes;
    struct timeval timeout = {TIMEOUT_SEC, 0};
    fd_set read_fds;
    int retval;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        error_exit("socket");

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0)
        error_exit("inet_pton");

    uint16_t prev_seq_num = 0;
    char prev_input[MAXSIZE] = "";

    while (true) {
        printf("문자열입력 : ");
        fgets(input_str, MAXSIZE, stdin);
        input_str[strcspn(input_str, "\n")] = '\0'; // Remove newline
        seq_num = cal_seq(prev_seq_num, prev_input);
        uint16_t net_seq_num = htons(seq_num);
        //보낼 메시지 seq랑 내용포함해서생성 
        memcpy(message, &net_seq_num, sizeof(net_seq_num));
        strcpy(message + sizeof(net_seq_num), input_str);

        bool ack_received = false;
        do {
            if (sendto(sockfd, message, sizeof(net_seq_num) + strlen(input_str), 0,
                       (struct sockaddr *)&server_addr, addr_len) < 0)
                error_exit("sendto");  
            FD_ZERO(&read_fds);
            FD_SET(sockfd, &read_fds);

            retval = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);

            if (retval == -1) {
                error_exit("select");
            } else if (retval == 0) {
                printf("Timeout occurred. Retransmitting message.\n");
                timeout.tv_sec = TIMEOUT_SEC;
                timeout.tv_usec = 0;
            } else {
                num_bytes = recvfrom(sockfd, recv_buffer, MAXMSIZE, 0, NULL, NULL);
                if (num_bytes < 0)
                    error_exit("recvfrom");
                recv_buffer[num_bytes] = '\0';
                printf("Received echo: %s\n", recv_buffer + sizeof(uint16_t));
                ack_received = true;
            }
        } while (!ack_received);
        prev_seq_num = seq_num;
        strcpy(prev_input, input_str);
        if (strcasecmp(input_str, "QUIT") == 0)
            break;
    }

    close(sockfd);
    return 0;
}
