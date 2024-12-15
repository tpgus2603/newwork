

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>             // close()
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>         // sockaddr_in
#include <arpa/inet.h>          // inet_ntoa()
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFSIZE 1500
#define PORT 9000

// 소켓 함수 오류 출력 후 종료
void err_quit(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

// 소켓 함수 오류 출력
void err_display(const char *msg) {
    perror(msg);
}

// OpenSSL 초기화 함수
void InitOpenSSL() {
    SSL_load_error_strings();          // 오류 문자열 로드
    OpenSSL_add_ssl_algorithms();      // SSL 알고리즘 초기화
}

// OpenSSL 정리 함수
void CleanupOpenSSL() {
    EVP_cleanup();
}

// 서버 SSL 컨텍스트 생성
SSL_CTX* CreateServerContext() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();       // 최신 TLS 메서드 사용
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// 서버 SSL 컨텍스트 설정
void ConfigureServerContext(SSL_CTX *ctx) {
    // 서버 인증서 설정
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // 서버 개인 키 설정
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // 개인 키 유효성 검사
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char* argv[]) {
    int listen_sock, client_sock;
    struct sockaddr_in serveraddr, clientaddr;
    socklen_t addrlen;
    char buf[BUFSIZE + 1];
    int retval, msglen;

    SSL_CTX *ctx;
    SSL *ssl;

    // OpenSSL 초기화
    InitOpenSSL();

    // SSL 컨텍스트 생성 및 설정
    ctx = CreateServerContext();
    ConfigureServerContext(ctx);

    // socket()
    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock < 0) err_quit("socket()");

    // 서버 주소 설정
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(PORT);
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);

    // bind()
    retval = bind(listen_sock, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
    if (retval < 0) err_quit("bind()");

    // listen()
    retval = listen(listen_sock, SOMAXCONN);
    if (retval < 0) err_quit("listen()");

    printf("[TCP Server] Listening on port %d with SSL...\n", PORT);

    while (1) {
        // accept()
        addrlen = sizeof(clientaddr);
        client_sock = accept(listen_sock, (struct sockaddr *)&clientaddr, &addrlen);
        if (client_sock < 0) {
            err_display("accept()");
            continue;
        }

        printf("\n[TCP Server] Client accepted: IP addr=%s, port=%d\n",
               inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port));

        // SSL 객체 생성 및 설정
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_sock);

        // SSL 핸드셰이크
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_sock);
            continue;
        }

        printf("[TCP Server] SSL connection established with client.\n");

        // 클라이언트와 데이터 통신
        while (1) {
            // 데이터 받기
            msglen = SSL_read(ssl, buf, BUFSIZE);
            if (msglen <= 0) {
                ERR_print_errors_fp(stderr);
                break;
            }

            // 받은 데이터 출력
            buf[msglen] = '\0';
            printf("[TCP/%s:%d] %s\n", inet_ntoa(clientaddr.sin_addr),
                   ntohs(clientaddr.sin_port), buf);

            // 데이터 보내기 (에코)
            retval = SSL_write(ssl, buf, msglen);
            if (retval <= 0) {
                ERR_print_errors_fp(stderr);
                break;
            }
        }

        // SSL 연결 종료 및 자원 정리
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_sock);
        printf("[TCP 서버] 클라이언트 종료: IP 주소=%s, 포트 번호=%d\n",
               inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port));
    }

    // 소켓 닫기
    close(listen_sock);

    // SSL 컨텍스트 정리
    SSL_CTX_free(ctx);
    CleanupOpenSSL();

    return 0;
}
