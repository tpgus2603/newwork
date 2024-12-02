// server.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>         
#include <arpa/inet.h>      
#include <pthread.h>        
#include <time.h>           // for time()

#define SERVER_PORT 3000
#define BUFFER_SIZE 1024
#define NICKNAME_LEN 32
#define MAX_CLIENTS 100

typedef struct {
    char nickname[NICKNAME_LEN];
    struct sockaddr_in addr;
} client_info;

// 클라이언트 목록과 관련 뮤텍스
client_info clients[MAX_CLIENTS];
int client_count = 0;
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

// 채팅 통계와 관련 변수 및 뮤텍스
int total_messages = 0;
pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;

time_t start_time;

// 메시지 처리 스레드 함수
void* handle_messages(void* arg) {
    int sockfd = *(int*)arg;
    char buffer[BUFFER_SIZE + NICKNAME_LEN + 3];
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    ssize_t recv_len;

    while (1) {
        // 클라이언트로부터 메시지 수신
        recv_len = recvfrom(sockfd, buffer, sizeof(buffer) - 1, 0,
                            (struct sockaddr*)&client_addr, &addr_len);
        if (recv_len == -1) {
            perror("recvfrom 실패");
            continue;
        }

        buffer[recv_len] = '\0'; // 문자열 종료

        // 클라이언트 정보 등록
        pthread_mutex_lock(&clients_mutex);
        int i;
        int found = 0;
        for (i = 0; i < client_count; i++) {
            if (clients[i].addr.sin_addr.s_addr == client_addr.sin_addr.s_addr &&
                clients[i].addr.sin_port == client_addr.sin_port) {
                found = 1;
                break;
            }
        }
        if (!found && client_count < MAX_CLIENTS) {
            // 새로운 클라이언트 등록
            // 메시지 형식: [닉네임] 메시지, 닉네임 추출
            if (buffer[0] == '[') {
                char* end_bracket = strchr(buffer, ']');
                if (end_bracket != NULL && (end_bracket - buffer - 1) < NICKNAME_LEN) {
                    strncpy(clients[client_count].nickname, buffer + 1, end_bracket - buffer - 1);
                    clients[client_count].nickname[end_bracket - buffer - 1] = '\0';
                } else {
                    strncpy(clients[client_count].nickname, "Unknown", NICKNAME_LEN - 1);
                    clients[client_count].nickname[NICKNAME_LEN - 1] = '\0';
                }
            } else {
                strncpy(clients[client_count].nickname, "Unknown", NICKNAME_LEN - 1);
                clients[client_count].nickname[NICKNAME_LEN - 1] = '\0';
            }

            // 클라이언트 주소 저장
            memset(&clients[client_count].addr, 0, sizeof(clients[client_count].addr));
            clients[client_count].addr.sin_family = AF_INET;
            clients[client_count].addr.sin_port = client_addr.sin_port;
            clients[client_count].addr.sin_addr.s_addr = client_addr.sin_addr.s_addr;

            client_count++;
            printf("새로운 클라이언트 등록: %s:%d\n",
                   inet_ntoa(client_addr.sin_addr),
                   ntohs(client_addr.sin_port));
        }
        pthread_mutex_unlock(&clients_mutex);

        // 메시지 통계 업데이트
        pthread_mutex_lock(&stats_mutex);
        total_messages++;
        pthread_mutex_unlock(&stats_mutex);

        // 다른 클라이언트에게 메시지 전달
        pthread_mutex_lock(&clients_mutex);
        for (i = 0; i < client_count; i++) {
            // 메시지를 보낸 클라이언트를 제외한 모든 클라이언트에게 전송
            if (clients[i].addr.sin_addr.s_addr != client_addr.sin_addr.s_addr ||
                clients[i].addr.sin_port != client_addr.sin_port) {
                if (sendto(sockfd, buffer, recv_len, 0,
                           (struct sockaddr*)&clients[i].addr, sizeof(clients[i].addr)) == -1) {
                    perror("sendto 실패");
                }
            }
        }
        pthread_mutex_unlock(&clients_mutex);
    }

    pthread_exit(NULL);
}

// 관리자 스레드 함수
void* admin_menu(void* arg) {
    int sockfd = *(int*)arg;
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
            case 1:
                // 클라이언트 정보 출력
                pthread_mutex_lock(&clients_mutex);
                printf("\n--- 클라이언트 정보 ---\n");
                printf("연결된 클라이언트 수: %d\n", client_count);
                for (int i = 0; i < client_count; i++) {
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(clients[i].addr.sin_addr), ip, INET_ADDRSTRLEN);
                    printf("닉네임: %s, IP: %s, 포트: %d\n",
                           clients[i].nickname,
                           ip,
                           ntohs(clients[i].addr.sin_port));
                }
                pthread_mutex_unlock(&clients_mutex);
                break;

             case 2:
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

            case 3:
                // 서버 종료
                printf("서버를 종료합니다.\n");
                close(sockfd);
                exit(EXIT_SUCCESS);
                break;

            default:
                printf("잘못된 선택입니다. 다시 시도하세요.\n");
                break;
        }
    }

    pthread_exit(NULL);
}

int main() {
    int sockfd;
    struct sockaddr_in server_addr;
    pthread_t message_thread, admin_thread;

    // 서버 시작 시간 기록
    start_time = time(NULL);

    // UDP 소켓 생성
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket 생성 실패");
        exit(EXIT_FAILURE);
    }

    // 서버 주소 설정
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr("172.21.54.201"); // 서버 IP 고정

    // 소켓 바인드
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind 실패");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("서버가 포트 %d에서 시작되었습니다.\n", SERVER_PORT);

    // 메시지 처리 스레드 생성
    if (pthread_create(&message_thread, NULL, handle_messages, &sockfd) != 0) {
        perror("메시지 처리 스레드 생성 실패");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 관리자 스레드 생성
    if (pthread_create(&admin_thread, NULL, admin_menu, &sockfd) != 0) {
        perror("관리자 스레드 생성 실패");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 스레드 종료 대기
    pthread_join(message_thread, NULL);
    pthread_join(admin_thread, NULL);

    // 소켓 닫기
    close(sockfd);

    return 0;
}
