#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>

#define SERVER_PORT 8080
#define MAX_MESSAGE_SIZE 1026 

void error_exit(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

double random_p() {
    int rand_int = rand() % 11; // 0부터 10 사이의 정수 생성
    return rand_int / 10.0;     // 10으로 나누어 0.0부터 1.0 사이의 값 생성 대략 1/11확률 
}

int main(int argc, char *argv[]) {
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char buffer[MAX_MESSAGE_SIZE];
    ssize_t num_bytes;
    uint16_t seq_num;
    char client_ip[INET_ADDRSTRLEN];
    double p = 0.5; 
    int N1 = 0, N2 = 0, N3 = 0, N = 0;

    if (argc == 2) { //확률값 p입력받기 가능 
        p = atof(argv[1]);
        if (p < 0.0 || p > 1.0) {
            fprintf(stderr, "Probability p must be between 0 and 1.\n");
            exit(EXIT_FAILURE);
        }
    }
    srand(time(NULL));
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        error_exit("socket");

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        error_exit("bind");

    bool client_terminated = false;

    while (!client_terminated) {
        memset(buffer,0,sizeof(buffer));
        num_bytes = recvfrom(sockfd, buffer, MAX_MESSAGE_SIZE, 0,
                             (struct sockaddr *)&client_addr, &addr_len);
        if (num_bytes < 0)
            error_exit("recvfrom");

        // seq랑 input메시지 추출하기 
        memcpy(&seq_num, buffer, sizeof(uint16_t));
        seq_num = ntohs(seq_num);
        char *input_str = buffer + sizeof(uint16_t);

        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

        printf("Client (%s:%d)로 부터 받은 메시지 : [%u][%s]\n",
               client_ip, ntohs(client_addr.sin_port), seq_num, input_str);
        double rand_prob = random_p();
        if (rand_prob <= p) {
            
            if (sendto(sockfd, buffer, num_bytes, 0,
                       (struct sockaddr *)&client_addr, addr_len) < 0)
                error_exit("sendto");
            printf("메세지 echo완료\n");
            N1++;
            // 대소문자 구별없이 받아들임 
            if (strcasecmp(input_str, "QUIT") == 0) {
                printf("Client (%s:%d) 종료\n", client_ip, ntohs(client_addr.sin_port));
                client_terminated = true;
            }
        } else {
            printf("메세지 손실 처리\n");
            N2++; // Increment retransmitted messages count
        } 
    }
    N3 = N1 + N2;
    N = N1 + N2;
    double retransmission_rate = (double)N2 / N;
    printf("통계정보: p=%.2f, N1=%d, N2=%d, N3=%d, R=%.2f\n",
           p, N1, N2, N3, retransmission_rate);

    close(sockfd);
    return 0;
}
