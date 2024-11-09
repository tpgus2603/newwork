#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>         // close() 함수 사용
#include <arpa/inet.h>      // inet_addr(), htons() 등 사용
#include <sys/socket.h>     // 소켓 함수들 사용
#include <netinet/in.h>     // sockaddr_in 구조체 사용
#include <errno.h>          // errno 사용

#define BUFSIZE 2024

// 오류 처리 함수
void err_quit(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

int main(int argc, char* argv[]) {
    if(argc != 3) {
        printf("Usage: %s <Server IP> <Port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    char* server_ip = argv[1];
    int server_port = atoi(argv[2]);

    int sock;
    struct sockaddr_in serveraddr;
    char send_buf[BUFSIZE];
    char recv_buf[BUFSIZE];
    int retval;

    // 소켓 생성
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock == -1) {
        err_quit("socket()");
    }

    // 서버 주소 설정
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(server_port);
    serveraddr.sin_addr.s_addr = inet_addr(server_ip);

    printf("UDP Echo Client is running. Server: %s:%d\n", server_ip, server_port);

    while(1) {
        char opt_input[10];
        unsigned short opt;
        char message[BUFSIZE];

        // 동작 선택
        printf("\n opt선택 (echo,chat,stat,quit): ");
        scanf("%s", opt_input);

        // 동작 코드 설정
        if(strcmp(opt_input, "echo") == 0) {
            opt = 0x0001;
        }
        else if(strcmp(opt_input, "chat") == 0) {
            opt = 0x0002;
        }
        else if(strcmp(opt_input, "stat") == 0) {
            opt = 0x0003;
        }
        else if(strcmp(opt_input, "quit") == 0) {
            opt = 0x0004;
        }
        else {
            printf("잘못된 옵션입니다. 다시 시도하세요.\n");
            // 입력 버퍼 정리
            while(getchar() != '\n');
            continue;
        }

        // 메시지 입력 (quit은 메시지가 필요 없음)
        if(strcmp(opt_input, "quit") != 0) {
            printf("Enter message: ");
            getchar(); // 이전 입력 버퍼 제거
            fgets(message, sizeof(message), stdin);
            // 개행 문자 제거
            int len = strlen(message);
            if(len > 0 && message[len-1] == '\n') {
                message[len-1] = '\0';
            }
        }

        // 전송 버퍼 구성
        memset(send_buf, 0, BUFSIZE);
        send_buf[0] = (opt >> 8) & 0xFF; // 상위 바이트
        send_buf[1] = opt & 0xFF;        // 하위 바이트

        if(strcmp(opt_input, "quit") != 0) {
            memcpy(send_buf + 2, message, strlen(message));
        }

        // 메시지 전송
        int send_len = (strcmp(opt_input, "quit") == 0) ? 2 : 2 + strlen(message);
        retval = sendto(sock, send_buf, send_len, 0, (struct sockaddr*)&serveraddr, sizeof(serveraddr));
        if(retval == -1) {
            perror("sendto() 오류");
            continue;
        }

        // 'quit' 동작 시 클라이언트 종료
        if(strcmp(opt_input, "quit") == 0) {
            printf("Quit 명령을 보냈습니다. 클라이언트를 종료합니다.\n");
            break;
        }

        // 응답 수신
        memset(recv_buf, 0, BUFSIZE);
        retval = recvfrom(sock, recv_buf, BUFSIZE, 0, NULL, NULL);
        if(retval == -1) {
            perror("recvfrom() 오류");
            continue;
        }

        recv_buf[retval] = '\0'; // 문자열 끝에 NULL 추가
        printf("서버로부터 수신: %s\n", recv_buf);
    }

    // 소켓 닫기
    close(sock);
    return 0;
}
