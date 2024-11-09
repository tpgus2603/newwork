// client.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>         
#include <arpa/inet.h>      
#include <pthread.h>       
#include <signal.h>         

#define SERVER_PORT 3000
#define BUFFER_SIZE 1024
#define NICKNAME_LEN 32

typedef struct {
    int sockfd;
    char nickname[NICKNAME_LEN];
} client_info;

// 종료 플래그
volatile sig_atomic_t exit_flag = 0;

// 메시지 전송 스레드 함수
void* send_message(void* arg) {
    client_info* client = (client_info*)arg;
    char message[BUFFER_SIZE];
    char send_buffer[BUFFER_SIZE + NICKNAME_LEN + 3]; // [닉네임] 메시지\0

    while (1) {
        printf("메시지 입력: ");
        if (fgets(message, sizeof(message), stdin) == NULL) {
            perror("fgets 실패");
            break;
        }

        // 개행 문자 제거
        message[strcspn(message, "\n")] = '\0';
        // 'exit' 입력 시 종료
        if (strcmp(message, "exit") == 0) {
            exit_flag = 1;
            break;
        }
        // 메시지 형식 지정
        snprintf(send_buffer, sizeof(send_buffer), "[%s] %s", client->nickname, message);
        // 메시지 전송
        if (send(client->sockfd, send_buffer, strlen(send_buffer), 0) == -1) {
            perror("send 실패");
            break;
        }
    }
    pthread_exit(NULL);
}

// 메시지 수신 스레드 함수
void* receive_message(void* arg) {
    client_info* client = (client_info*)arg;
    char buffer[BUFFER_SIZE + NICKNAME_LEN + 3]; // [닉네임] 메시지\0

    while (1) {
        memset(buffer, 0, sizeof(buffer));
        int retval = recv(client->sockfd, buffer, sizeof(buffer) - 1, 0);
        if (retval > 0) {
            buffer[retval] = '\0';
            printf("\n%s\n메시지 입력: ", buffer);
            fflush(stdout);
        } else if (retval == 0) {
            printf("\n서버와의 연결이 끊어졌습니다.\n");
            exit_flag = 1;
            break;
        } else {
            perror("recv 실패");
            exit_flag = 1;
            break;
        }
    }
    pthread_exit(NULL);
}

// tcp는 시그널 핸들러를 구현해야함 (Ctrl+C)
void handle_sigint(int sig) {
    exit_flag = 1;
}

int main() {
    client_info client;
    pthread_t send_thread, recv_thread;
    char server_ip[] = "127.0.0.1"; // 서버 IP 고정

    // 연결종료에 대한 시그널 핸들러 
    signal(SIGINT, handle_sigint);

    // 닉네임 설정
    printf("닉네임을 입력하세요: ");
    if (fgets(client.nickname, sizeof(client.nickname), stdin) == NULL) {
        fprintf(stderr, "닉네임 입력 실패\n");
        exit(EXIT_FAILURE);
    }
    // 개행 문자 제거
    client.nickname[strcspn(client.nickname, "\n")] = '\0';

    // TCP 소켓 생성
    if ((client.sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket 생성 실패");
        exit(EXIT_FAILURE);
    }

    // 서버 주소 설정
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr=inet_addr(server_ip);
  
    // 서버에 연결
    if (connect(client.sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("connect 실패");
        close(client.sockfd);
        exit(EXIT_FAILURE);
    }

    // 닉네임 전송
    if (send(client.sockfd, client.nickname, strlen(client.nickname), 0) == -1) {
        perror("닉네임 전송 실패");
        close(client.sockfd);
        exit(EXIT_FAILURE);
    }

    printf("=== 채팅에 접속하였습니다. ===\n");

    // 메시지 전송 스레드 생성
    if (pthread_create(&send_thread, NULL, send_message, &client) != 0) {
        perror("전송 스레드 생성 실패");
        close(client.sockfd);
        exit(EXIT_FAILURE);
    }

    // 메시지 수신 스레드 생성
    if (pthread_create(&recv_thread, NULL, receive_message, &client) != 0) {
        perror("수신 스레드 생성 실패");
        close(client.sockfd);
        exit(EXIT_FAILURE);
    }
    pthread_detach(recv_thread);
    pthread_detach(send_thread);

    //종료 플래그를 확인하며 대기 시그널 기반으로 대기(join안씀) 종료시킴
    while (!exit_flag) {
        sleep(1);
    }

    // 소켓 닫기
    close(client.sockfd);
    printf("채팅을 종료합니다.\n");

    return 0;
}
