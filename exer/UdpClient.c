
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>         
#include <arpa/inet.h>    

#define BUFSIZE 2024

int main(int argc, char* argv[]) {
    if(argc != 3) {
        printf("Usage: %s <Server IP> <Port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    char* server_ip = argv[1];
    int server_port = atoi(argv[2]);


    char send_buf[BUFSIZE];
    char recv_buf[BUFSIZE];
    int retval;

    // 윈속 초기화

    // 소켓 생성
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock == -1) {
        perror("소켓생성실패");
        return EXIT_FAILURE;
    }
    struct  sockaddr_in serveraddr;
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

        // 동작 형식 코드 가져오기
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
            printf("wrong opt. Please try again.\n");
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
            fprintf(stderr, "sendto() error: %d\n");
            continue;
        }
        // 'quit' 동작 시 클라이언트 종료
        if(strcmp(opt_input, "quit") == 0) {
            printf("Quit command sent. Exiting client.\n");
            break;
        }

        // 응답 수신
        memset(recv_buf, 0, BUFSIZE);
        retval = recvfrom(sock, recv_buf, BUFSIZE, 0, NULL, NULL);
        if(retval == -1) {
            continue;
        }

        recv_buf[retval] = '\0'; // 문자열 끝에 NULL 추가
        printf("Received from server: %s\n", recv_buf);
    }

    // 소켓 닫기 및 윈속 종료
    close(sock);
    return 0;
}
