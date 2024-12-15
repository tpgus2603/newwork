

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>             
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>         // sockaddr_in
#include <arpa/inet.h>          // inet_pton()
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

// 클라이언트 SSL 컨텍스트 생성
SSL_CTX* CreateClientContext() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();       // 최신 TLS 메서드 사용
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

int main(int argc, char* argv[]) {
    int retval;
    int sock;
    struct sockaddr_in serveraddr;
    char buf[BUFSIZE + 1];
    int len;

    SSL_CTX *ctx;
    SSL *ssl;

    // OpenSSL 초기화
    InitOpenSSL();

    // SSL 컨텍스트 생성
    ctx = CreateClientContext();

    // socket()
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) err_quit("socket()");

    // 서버 주소 설정
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(PORT);

    // 서버 IP 주소 설정 (예: localhost)
    if (inet_pton(AF_INET, "127.0.0.1", &serveraddr.sin_addr) <= 0) {
        err_quit("inet_pton() failed");
    }

    // connect()
    retval = connect(sock, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
    if (retval < 0) err_quit("connect()");

    printf("[TCP 클라이언트] 서버에 연결되었습니다.\n");

    // SSL 객체 생성 및 설정
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    // SSL 핸드셰이크
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        CleanupOpenSSL();
        exit(EXIT_FAILURE);
    }

    printf("[TCP 클라이언트] SSL connection established with server.\n");

    // 서버와 데이터 통신
    while (1) {
        // 데이터 입력
        memset(buf, 0, sizeof(buf));
        printf("\n[보낼 데이터] ");
        if (fgets(buf, BUFSIZE + 1, stdin) == NULL)
            break;

        // '\n' 문자 제거
        len = strlen(buf);
        if (buf[len - 1] == '\n')
            buf[len - 1] = '\0';
        if (strlen(buf) == 0)
            break;

        // 데이터 보내기
        retval = SSL_write(ssl, buf, strlen(buf));
        if (retval <= 0) {
            ERR_print_errors_fp(stderr);
            break;
        }
        printf("[TCP 클라이언트] %d바이트를 보냈습니다.\n", retval);

        // 데이터 받기
        retval = SSL_read(ssl, buf, BUFSIZE);
        if (retval <= 0) {
            ERR_print_errors_fp(stderr);
            break;
        }

        // 받은 데이터 출력
        buf[retval] = '\0';
        printf("[TCP 클라이언트] %d바이트를 받았습니다.\n", retval);
        printf("[받은 데이터] %s\n", buf);
    }

    // SSL 연결 종료 및 자원 정리
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);

    // SSL 컨텍스트 정리
    SSL_CTX_free(ctx);
    CleanupOpenSSL();

    return 0;
}
