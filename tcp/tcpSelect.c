// Linux에서 여러 클라이언트를 처리하는 서버 예제

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>

#define PORT 8080
#define MAX_CLIENTS 30

int main() {
    int master_socket, new_socket, client_socket[MAX_CLIENTS], activity, i, valread, sd;
    int max_sd;
    struct sockaddr_in address;
    char buffer[1025];

    fd_set readfds;

    // 클라이언트 소켓 배열 초기화
    for (i = 0; i < MAX_CLIENTS; i++)
        client_socket[i] = 0;

    // 마스터 소켓 설정
    if ((master_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("소켓 생성 실패");
        exit(EXIT_FAILURE);
    }

    // 소켓 옵션 설정
    int opt = 1;
    if (setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt 실패");
        exit(EXIT_FAILURE);
    }

    // 주소 설정
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // 바인드
    if (bind(master_socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("바인드 실패");
        exit(EXIT_FAILURE);
    }

    // 리슨
    if (listen(master_socket, 3) < 0) {
        perror("리슨 실패");
        exit(EXIT_FAILURE);
    }

    printf("서버가 포트 %d에서 시작되었습니다.\n", PORT);

    while (1) {
        // fd_set 초기화
        FD_ZERO(&readfds);

        // 마스터 소켓 추가
        FD_SET(master_socket, &readfds);
        max_sd = master_socket;

        // 클라이언트 소켓 추가
        for (i = 0; i < MAX_CLIENTS; i++) {
            sd = client_socket[i];

            if (sd > 0)
                FD_SET(sd, &readfds);

            if (sd > max_sd)
                max_sd = sd;
        }

        // select 호출
        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);

        if ((activity < 0) && (errno != EINTR)) {
            printf("select 오류\n");
        }

        // 마스터 소켓에서의 활동 체크 (새로운 연결)
        if (FD_ISSET(master_socket, &readfds)) {
            int addrlen = sizeof(address);
            if ((new_socket = accept(master_socket, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
                perror("accept 실패");
                exit(EXIT_FAILURE);
            }

            printf("새로운 연결, 소켓 FD는 %d , IP는 : %s , 포트 : %d\n", new_socket, inet_ntoa(address.sin_addr), ntohs(address.sin_port));

            // 클라이언트 소켓 배열에 추가
            for (i = 0; i < MAX_CLIENTS; i++) {
                if (client_socket[i] == 0) {
                    client_socket[i] = new_socket;
                    printf("소켓을 배열에 추가함: %d\n", i);
                    break;
                }
            }
        }

        // 클라이언트 소켓에서의 활동 체크
        for (i = 0; i < MAX_CLIENTS; i++) {
            sd = client_socket[i];

            if (FD_ISSET(sd, &readfds)) {
                // 읽기 작업 수행
                if ((valread = read(sd, buffer, 1024)) == 0) {
                    // 연결 종료
                    getpeername(sd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
                    printf("클라이언트 연결 종료, IP %s , 포트 %d \n", inet_ntoa(address.sin_addr), ntohs(address.sin_port));

                    close(sd);
                    client_socket[i] = 0;
                } else {
                    // 데이터 처리
                    buffer[valread] = '\0';
                    send(sd, buffer, strlen(buffer), 0);
                }
            }
        }
    }

    return 0;
}
