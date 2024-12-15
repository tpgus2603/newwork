
// UDP Echo Server with DTLS for Linux

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

#define BUFSIZE 512
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
    SSL_library_init();                // SSL 라이브러리 초기화
}

// OpenSSL 정리 함수
void CleanupOpenSSL() {
    EVP_cleanup();
}

// 서버 DTLS 컨텍스트 생성
SSL_CTX* CreateServerContext() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = DTLS_server_method();      // DTLS 메서드 사용
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// 서버 DTLS 컨텍스트 설정
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

    // 인증서 검증 비활성화 (테스트 용도로만 사용)
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
}

int main(int argc, char* argv[]) {
    int retval;
    int sock;
    struct sockaddr_in serveraddr, clientaddr;
    socklen_t addrlen;
    char buf[BUFSIZE + 1];

    SSL_CTX *ctx;
    SSL *ssl;

    // OpenSSL 초기화
    InitOpenSSL();

    // DTLS 컨텍스트 생성 및 설정
    ctx = CreateServerContext();
    ConfigureServerContext(ctx);

    // 소켓 생성
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) err_quit("socket()");

    // 서버 주소 구조체 초기화
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(PORT);
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);

    // bind()
    retval = bind(sock, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
    if(retval < 0) err_quit("bind()");

    printf("[DTLS 서버] 포트 %d에서 대기 중...\n", PORT);

    while(1){
        // 클라이언트 주소 초기화
        addrlen = sizeof(clientaddr);
        memset(&clientaddr, 0, sizeof(clientaddr));

        // 데이터 받기
        retval = recvfrom(sock, buf, BUFSIZE, 0, (struct sockaddr *)&clientaddr, &addrlen);
        if(retval < 0){
            err_display("recvfrom()");
            continue;
        }

        // 받은 데이터 출력
        buf[retval] = '\0';
        printf("[DTLS/UDP/%s:%d] %s\n", inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port), buf);

        // DTLS 객체 생성 및 설정
        ssl = SSL_new(ctx);
        BIO *bio = BIO_new_dgram(sock, BIO_NOCLOSE);
        BIO_dgram_set_peer(bio, (struct sockaddr*)&clientaddr); // 수정된 부분
        SSL_set_bio(ssl, bio, bio);

        // DTLS 핸드셰이크
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            continue;
        }

        printf("[DTLS 서버] DTLS 연결이 설정되었습니다.\n");

        // 데이터 보내기 (에코)
        retval = SSL_write(ssl, buf, retval);
        if(retval <= 0){
            ERR_print_errors_fp(stderr);
        } else {
            printf("[DTLS 서버] %d바이트를 보냈습니다.\n", retval);
        }

        // DTLS 연결 종료 및 자원 정리
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }

    // 소켓 닫기
    close(sock);

    // DTLS 컨텍스트 정리
    SSL_CTX_free(ctx);
    CleanupOpenSSL();

    return 0;
}
