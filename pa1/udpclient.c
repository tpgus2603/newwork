// client.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>         
#include <arpa/inet.h>      
#include <pthread.h>        

#define SERVER_PORT 3000
#define BUFFER_SIZE 1024
#define NICKNAME_LEN 32

typedef struct {
    int sockfd;
    struct sockaddr_in server_addr;
    char nickname[NICKNAME_LEN];
} client_info;

// 전송 스레드 함수
void* send_message(void* arg) {
    client_info* client = (client_info*)arg;
    char message[BUFFER_SIZE];
    char send_buffer[BUFFER_SIZE + NICKNAME_LEN + 3]; // [닉네임] 메시지\0
    while (1) {
        // 사용자로부터 메시지 입력
        printf("메시지 입력: ");
        if (fgets(message, sizeof(message), stdin) == NULL) {
            perror("fgets 실패");
            break;
        }
        // 입력한 메시지의 개행 문자 제거
        message[strcspn(message, "\n")] = '\0';

        // 메시지 형식 지정
        snprintf(send_buffer, sizeof(send_buffer), "[%s] %s", client->nickname, message);

        // 서버로 메시지 전송
        if (sendto(client->sockfd, send_buffer, strlen(send_buffer), 0,
                   (struct sockaddr*)&client->server_addr, sizeof(client->server_addr)) == -1) {
            perror("sendto 실패");
            break;
        }
    }

    pthread_exit(NULL);
}

// 수신 스레드 함수
void* receive_message(void* arg) {
    client_info* client = (client_info*)arg;
    char recv_buffer[BUFFER_SIZE + NICKNAME_LEN + 3]; //[닉네임] 메시지 형식에 맞게 크기조정 
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    ssize_t recv_len;

    while (1) {
        // 서버로부터 메시지 수신
        recv_len = recvfrom(client->sockfd, recv_buffer, sizeof(recv_buffer) - 1, 0,
                            (struct sockaddr*)&from_addr, &from_len);
        if (recv_len == -1) {
            perror("recvfrom 실패");
            break;
        }

        // 수신한 메시지를 문자열로 변환
        recv_buffer[recv_len] = '\0';
        // 메시지 출력
        printf("\n%s\n", recv_buffer);
        printf("메시지 입력: ");
        fflush(stdout);
    }

    pthread_exit(NULL);
}

int main() {
    client_info client;
    pthread_t send_thread, recv_thread;
    char server_ip[] = "127.0.0.1"; // 서버 IP 고정

    // 닉네임 설정
    printf("닉네임을 입력하세요: ");
    if (fgets(client.nickname, sizeof(client.nickname), stdin) == NULL) {
        fprintf(stderr, "닉네임 입력 실패\n");
        exit(EXIT_FAILURE);
    }
    // 개행 문자 제거
    client.nickname[strcspn(client.nickname, "\n")] = '\0';

    // UDP 소켓 생성
    if ((client.sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket 생성 실패");
        exit(EXIT_FAILURE);
    }

    // 서버 주소 설정
    memset(&client.server_addr, 0, sizeof(client.server_addr));
    client.server_addr.sin_family = AF_INET;
    client.server_addr.sin_port = htons(SERVER_PORT);
    client.server_addr.sin_addr.s_addr = inet_addr(server_ip); // 서버 IP 고정

    // 초기 접속 메시지 전송
    char join_message[BUFFER_SIZE + NICKNAME_LEN + 3];
    snprintf(join_message, sizeof(join_message), "[%s] has joined the chat", client.nickname);
    int retval=sendto(client.sockfd,join_message,strlen(join_message),0,
    (struct sockaddr*)&client.server_addr,sizeof(client.server_addr));
    if(retval==-1)
    {
        perror("send error!");
        close(client.sockfd);
        exit(EXIT_FAILURE);
    }

    // 전송 스레드 생성
    if (pthread_create(&send_thread, NULL, send_message, &client) != 0) {
        perror("전송 스레드 생성 실패");
        close(client.sockfd);
        exit(EXIT_FAILURE);
    }

    // 수신 스레드 생성
    if (pthread_create(&recv_thread, NULL, receive_message, &client) != 0) {
        perror("수신 스레드 생성 실패");
        close(client.sockfd);
        exit(EXIT_FAILURE);
    }

    // 스레드 종료 대기
    pthread_join(send_thread, NULL);
    pthread_join(recv_thread, NULL);

    // 소켓 닫기
    close(client.sockfd);

    return 0;
}
