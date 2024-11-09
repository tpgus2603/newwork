// UdpServer.c
// UDP Server

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>         // close() 함수 사용
#include <arpa/inet.h>      // inet_addr(), htons(), inet_ntoa() 등 사용
#include <sys/socket.h>     // 소켓 함수들 사용
#include <netinet/in.h>     // sockaddr_in 구조체 사용
#include <errno.h>          // errno 사용

#define BUFSIZE 2048

// 오류 처리 함수
void err_quit(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <Server IP> <Port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *server_ip = argv[1];
    int server_port = atoi(argv[2]);

    int sock;
    struct sockaddr_in serveraddr, clientaddr;
    char buf[BUFSIZE];
    socklen_t clientaddr_len;
    int retval;

    // 소켓 생성
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        err_quit("socket()");
    }

    // 서버 주소 설정
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(server_port);
    serveraddr.sin_addr.s_addr = inet_addr(server_ip);

    // 바인딩
    if (bind(sock, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) == -1) {
        err_quit("bind()");
    }

    printf("UDP Echo Server is running on %s:%d\n", server_ip, server_port);

    unsigned long total_bytes = 0;
    unsigned long total_messages = 0;

    while (1) {
        clientaddr_len = sizeof(clientaddr);

        memset(buf, 0, BUFSIZE);
        retval = recvfrom(sock, buf, BUFSIZE, 0, (struct sockaddr *)&clientaddr, &clientaddr_len);

        if (retval == -1) {
            perror("recvfrom() error");
            continue;
        }

        total_bytes += retval;
        total_messages += 1;

        char client_ip[INET_ADDRSTRLEN];
        strcpy(client_ip, inet_ntoa(clientaddr.sin_addr));
        unsigned short client_port = ntohs(clientaddr.sin_port);

        // 옵션 코드 추출
        unsigned short opt = ((unsigned char)buf[0] << 8) | (unsigned char)buf[1];
        char *message = buf + 2;
        int message_len = retval - 2;
        printf("client에게 받은 메세지: %s\n", message);
        char send_buf[BUFSIZE];
        memset(send_buf, 0, BUFSIZE);

        switch (opt) {
            case 0x0001: { // ECHO
                char echo_response[BUFSIZE];

                // 형식 문자열 포함해서 문자열 생성
                snprintf(echo_response, BUFSIZE, "(%s:%d)가 (%s:%d)로부터 (%d) 바이트 메시지 수신: %.*s",
                         client_ip, client_port, server_ip, server_port, message_len, message_len, message);

                int response_len = strlen(echo_response);
                memcpy(send_buf, echo_response, response_len);
                retval = sendto(sock, send_buf, response_len, 0, (struct sockaddr *)&clientaddr, clientaddr_len);
                if (retval == -1) {
                    perror("sendto() echo error");
                }
            }
            break;

            case 0x0002: { // CHAT
                char server_reply[BUFSIZE];
                printf("클라이언트 (%s:%d)에게 보낼 chat 메시지를 입력: ", client_ip, client_port);
                if (fgets(server_reply, sizeof(server_reply), stdin) == NULL) {
                    fprintf(stderr, "채팅 메시지 입력 오류.\n");
                    break;
                }

                int len = strlen(server_reply);
                if (len > 0 && server_reply[len - 1] == '\n') {
                    server_reply[len - 1] = '\0';
                }
                int reply_len = strlen(server_reply);
                char chat_response[BUFSIZE];
                snprintf(chat_response, BUFSIZE, "(%s:%d)가 (%s:%d)로부터 (%d) 바이트 메시지 수신: %.*s",
                         client_ip, client_port, server_ip, server_port, reply_len, reply_len, server_reply);
                int response_len = strlen(chat_response);
                memcpy(send_buf, chat_response, response_len);
                retval = sendto(sock, send_buf, response_len, 0, (struct sockaddr *)&clientaddr, clientaddr_len);
                if (retval == -1) {
                    perror("sendto() chat error");
                }

            }
            break;
            case 0x0003: { // STAT
                char *stat_request = message;
                char stat_response[BUFSIZE];
                memset(stat_response, 0, BUFSIZE);
                if (strncmp(stat_request, "bytes", 5) == 0) {
                    snprintf(stat_response, BUFSIZE, "Total bytes received: %lu", total_bytes);
                } else if (strncmp(stat_request, "number", 6) == 0) {
                    snprintf(stat_response, BUFSIZE, "Total messages received: %lu", total_messages);
                } else if (strncmp(stat_request, "both", 4) == 0) {
                    snprintf(stat_response, BUFSIZE, "Total messages received: %lu, Total bytes received: %lu", total_messages, total_bytes);
                } else {
                    snprintf(stat_response, BUFSIZE, "Invalid stat request.");
                }
                int stat_len = strlen(stat_response);
                char full_stat_response[BUFSIZE];
                snprintf(full_stat_response, BUFSIZE, "(%s:%d)가 (%s:%d)로부터 (%d) 바이트 메시지 수신: %.*s",
                         client_ip, client_port, server_ip, server_port, stat_len, stat_len, stat_response);
                int response_len = strlen(full_stat_response);
                memcpy(send_buf, full_stat_response, response_len);
                retval = sendto(sock, send_buf, response_len, 0, (struct sockaddr *)&clientaddr, clientaddr_len);
                if (retval == -1) {
                    perror("sendto() stat error");
                }

            }
            break;

            case 0x0004: { // QUIT
                printf(" 서버를 종료합니다.\n");
                close(sock);
                return EXIT_SUCCESS;
            }
            break;

            default: {
                printf("알 수 없는 동작 형식: 0x%04X\n", opt);
                break;
            }
        }
    }
    close(sock);
    return 0;
}
