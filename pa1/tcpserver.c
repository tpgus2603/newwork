// server.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>         
#include <arpa/inet.h>      
#include <pthread.h>        
#include <time.h>           
#define SERVER_PORT 3000
#define BUFFER_SIZE 1024
#define NICKNAME_LEN 32
#define MAX_CLIENTS 100

// 클라이언트 정보를 저장하는 구조체
typedef struct client_node {
    int sockfd;
    char nickname[NICKNAME_LEN];
    struct sockaddr_in addr;
    struct client_node *next;
} client_node;

// 클라이언트 리스트의 헤드 포인터와 뮤텍스
client_node *client_list_head = NULL;
pthread_mutex_t client_list_mutex = PTHREAD_MUTEX_INITIALIZER;

// 채팅 통계와 관련 변수 및 뮤텍스
int total_messages = 0;
pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;



time_t start_time;
// 클라이언트 리스트에 클라이언트 추가
void add_client(client_node *client) {
    pthread_mutex_lock(&client_list_mutex);
    client->next = client_list_head;
    client_list_head = client;
    pthread_mutex_unlock(&client_list_mutex);
}
// 클라이언트 리스트에서 클라이언트 제거
void remove_client(int sockfd) {
    pthread_mutex_lock(&client_list_mutex);
    client_node *prev = NULL;
    client_node *curr = client_list_head;
    while (curr != NULL) {
        if (curr->sockfd == sockfd) {
            if (prev == NULL) { //삭제할대상이 헤드인경우 
                client_list_head = curr->next;
            } else {
                prev->next = curr->next;
            }
            close(curr->sockfd);
            free(curr);
            break;
        }
        prev = curr;
        curr = curr->next;
    }
    pthread_mutex_unlock(&client_list_mutex);
}

// 모든 클라이언트에게 메시지 보냄
void handle_messages(char *message, int sender_sockfd) {
    pthread_mutex_lock(&client_list_mutex);
    client_node *curr = client_list_head;
    while (curr != NULL) {
        if (curr->sockfd != sender_sockfd) {
            if (send(curr->sockfd, message, strlen(message), 0) == -1) {
                perror("send 실패");
            }
        }
        curr = curr->next;
    }
    pthread_mutex_unlock(&client_list_mutex);
}

// 클라이언트와의 통신 및 메시지 전송 을 처리하는 스레드 함수
void* handle_client(void* arg) {
    client_node *client = (client_node*)arg;
    char buffer[BUFFER_SIZE];
    char message[BUFFER_SIZE]; // [닉네임] 메시지\0

    // 클라이언트로부터 닉네임 수신
    int recv_len = recv(client->sockfd, client->nickname, NICKNAME_LEN - 1, 0);
    if (recv_len <= 0 || strlen(client->nickname) < 2 || strlen(client->nickname) >= NICKNAME_LEN - 1) {
        printf("닉네임 수신 실패 또는 유효하지 않은 닉네임\n");
        close(client->sockfd);
        free(client);
        pthread_exit(NULL);
    }
    client->nickname[recv_len] = '\0';
    printf("클라이언트 %s 연결됨\n", client->nickname);
    printf("선택: \n");

    // 클라이언트 리스트에 추가
    add_client(client);

    // 클라이언트에게 접속 메시지 브로드캐스트
    snprintf(message, sizeof(message), "[%s] has joined the chat", client->nickname);
    handle_messages(message, client->sockfd);

    while (1) {
        memset(buffer, 0, sizeof(buffer));
        int retrval = recv(client->sockfd, buffer, sizeof(buffer), 0);
        if (retrval > 0) {
            // 메시지 포맷: [닉네임] 메시지
            fflush(stdout);
            // 메시지 브로드캐스트
            handle_messages(buffer, client->sockfd);
            // 통계 업데이트
            pthread_mutex_lock(&stats_mutex);
            total_messages++;
            pthread_mutex_unlock(&stats_mutex);
        } else if (retrval == 0) {
            // 클라이언트 연결 종료
            printf("클라이언트 [%s] 연결 종료\n",client->nickname);
            printf("선택: \n");
            remove_client(client->sockfd);
            break;
        } else {
            perror("recv 실패");
            remove_client(client->sockfd);
            break;
        }
    }
    pthread_exit(NULL);
}

// 관리자 메뉴를 처리하는 스레드 함수
void* admin_menu(void* arg) {
    int server_sockfd = *(int*)arg;
    int opt;
    char input[10];

    while (1) {
        printf("\n--- 서버 메뉴 ---\n");
        printf("1. 클라이언트 정보\n");
        printf("2. 채팅 통계\n");
        printf("3. 서버 종료\n");
        printf("선택: \n");
        if (fgets(input, sizeof(input), stdin) == NULL) {
            perror("fgets 실패");
            continue;
        }
        opt = atoi(input);
        switch (opt) {
            case 1: {
                // 클라이언트 정보 출력
                pthread_mutex_lock(&client_list_mutex);
                printf("\n--- 클라이언트 정보 ---\n");
                int count = 0;
                client_node *curr = client_list_head;
                while (curr != NULL) {
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(curr->addr.sin_addr), ip, INET_ADDRSTRLEN);
                    printf("닉네임: %s, IP: %s, 포트: %d\n",
                           curr->nickname,
                           ip,
                           ntohs(curr->addr.sin_port));
                    count++;
                    curr = curr->next;
                }
                printf("연결된 클라이언트 수: %d\n", count);
                pthread_mutex_unlock(&client_list_mutex);
                break;
            }
            case 2: {
                // 채팅 통계 출력
                pthread_mutex_lock(&stats_mutex);
                time_t current_time = time(NULL);
                double seconds = difftime(current_time, start_time);
                double avg_messages = (seconds > 0) ? ((double)total_messages * 60 / seconds) : 0.0;
                printf("\n--- 채팅 통계 ---\n");
                printf("총 메시지 수: %d\n", total_messages);
                printf("채팅 시작 후 경과 시간: %.2f 초\n", seconds);
                printf("평균 메시지 수: %.2f 메시지/분\n", avg_messages);
                pthread_mutex_unlock(&stats_mutex);
                break;
            }
            case 3: {
                // 서버 종료
                printf("서버를 종료합니다.\n");
                // 모든 클라이언트 소켓 닫기
                pthread_mutex_lock(&client_list_mutex);
                client_node *curr = client_list_head;
                while (curr != NULL) {
                    close(curr->sockfd);
                    curr = curr->next;
                }
                pthread_mutex_unlock(&client_list_mutex);
                close(server_sockfd);
                exit(EXIT_SUCCESS);
                break;
            }
            default:
                printf("잘못된 선택입니다. 다시 시도하세요.\n");
                break;
        }
    }

    pthread_exit(NULL);
}

int main() {
    int server_sockfd, client_sockfd;
    struct sockaddr_in server_addr, client_addr;
    pthread_t client_thread, admin_thread;

    // 서버 시작 시간 기록
    start_time = time(NULL);

    // TCP 소켓 생성
    if ((server_sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket 생성 실패");
        exit(EXIT_FAILURE);
    }

    // 소켓 옵션 설정 (주소 재사용)
    int option = 1;
    if (setsockopt(server_sockfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0) {
        perror("setsockopt 실패");
        close(server_sockfd);
        exit(EXIT_FAILURE);
    }

    // 서버 주소 설정
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY; // 모든 인터페이스에서 수신

    // 소켓 바인드
    if (bind(server_sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind 실패");
        close(server_sockfd);
        exit(EXIT_FAILURE);
    }

    // 리슨
    if (listen(server_sockfd, 10) == -1) {
        perror("listen 실패");
        close(server_sockfd);
        exit(EXIT_FAILURE);
    }

    printf("서버가 포트 %d에서 시작되었습니다.\n", SERVER_PORT);

    // 관리자 스레드 생성
    if (pthread_create(&admin_thread, NULL, admin_menu, (void*)&server_sockfd) != 0) {
        perror("관리자 스레드 생성 실패");
        close(server_sockfd);
        exit(EXIT_FAILURE);
    }

    while (1) {
        socklen_t addr_len = sizeof(client_addr);
        // 클라이언트 연결 수락
        if ((client_sockfd = accept(server_sockfd, (struct sockaddr*)&client_addr, &addr_len)) == -1) {
            perror("accept 실패");
            continue;
        }

        // 클라이언트 정보 생성
        client_node *new_client = (client_node*)malloc(sizeof(client_node));
        if (!new_client) {
            perror("malloc 실패");
            close(client_sockfd);
            continue;
        }
        new_client->sockfd = client_sockfd;
        new_client->addr = client_addr;
        memset(new_client->nickname, 0, NICKNAME_LEN);
        new_client->next = NULL;

        // 클라이언트와의 통신 스레드 생성
        if (pthread_create(&client_thread, NULL, handle_client, (void*)new_client) != 0) {
            perror("클라이언트 스레드 생성 실패");
            close(client_sockfd);
            free(new_client);
            continue;
        }

        // 스레드 분리 (자원이 join없이 자동 회수되도록)
        pthread_detach(client_thread);
    }

    close(server_sockfd);

    return 0;
}
