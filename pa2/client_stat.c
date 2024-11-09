#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h> // 랜덤 함수 사용을 위해 추가

#define SERVER_PORT 8080
#define TIMEOUT_SEC 1 // 타임아웃 시간을 1초로 변경
#define MAXSIZE 50
#define MAXMSIZE (2 + MAXSIZE) // 2 bytes for sequence number
#define K 100 // 전송할 랜덤 문자열의 개수 설정

void error_exit(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

uint16_t cal_seq(uint16_t prev_seq, const char *prev_input) {
    return prev_seq + strlen(prev_input);
}

// 랜덤 문자열을 생성하는 함수 추가
void generate_random_string(char *str, size_t max_len) {
    size_t len = rand() % (max_len - 1) + 1; // 1부터 max_len -1 사이의 길이로 문자열 길이 결정
    for (size_t i = 0; i < len; ++i) {
        str[i] = 'a' + rand() % 26; // 소문자 알파벳 랜덤 선택
    }
    str[len] = '\0'; // 문자열 종료 문자 추가
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
    struct timeval timeout;
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

    srand(time(NULL)); // 랜덤 시드 초기화

    int messages_sent = 0; // 전송한 메시지 수를 저장할 변수 추가

    while (true) {
        if (messages_sent < K) {
            generate_random_string(input_str, MAXSIZE); // 랜덤 문자열 생성하여 input_str에 저장
        } else {
            strcpy(input_str, "QUIT"); // K번 전송 후 "QUIT" 문자열 설정
        }

        seq_num = cal_seq(prev_seq_num, prev_input);
        uint16_t net_seq_num = htons(seq_num);
        // 보낼 메시지에 시퀀스 번호와 내용 포함하여 생성
        memcpy(message, &net_seq_num, sizeof(net_seq_num));
        strcpy(message + sizeof(net_seq_num), input_str);

        bool ack_received = false;
        do {
            if (sendto(sockfd, message, sizeof(net_seq_num) + strlen(input_str), 0,
                       (struct sockaddr *)&server_addr, addr_len) < 0)
                error_exit("sendto");

            FD_ZERO(&read_fds);
            FD_SET(sockfd, &read_fds);

            timeout.tv_sec = TIMEOUT_SEC; // 타임아웃 시간 1초로 설정
            timeout.tv_usec = 0;

            retval = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);

            if (retval == -1) {
                error_exit("select");
            } else if (retval == 0) {
                // 타임아웃 발생 시 재전송
                 //printf("Timeout occurred. Retransmitting message.\n"); // 출력 생략
            } else {
                num_bytes = recvfrom(sockfd, recv_buffer, MAXMSIZE, 0, NULL, NULL);
                if (num_bytes < 0)
                    error_exit("recvfrom");
                recv_buffer[num_bytes] = '\0';
                printf("Received echo: %s\n", recv_buffer + sizeof(uint16_t)); // 출력 생략
                ack_received = true;
            }
        } while (!ack_received);
        prev_seq_num = seq_num;
        strcpy(prev_input, input_str);

        messages_sent++; // 전송한 메시지 수 증가

        if (strcasecmp(input_str, "QUIT") == 0)
            break;
    }

    close(sockfd);
    return 0;
}
