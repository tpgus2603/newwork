#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

int main() {
    int sock;
    struct ifreq ifr;
    struct sockaddr_ll sll;
    unsigned char buffer[2048];

    // 소켓 생성
    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock == -1) {
        perror("Socket creation failed");
        return -1;
    }

    // 네트워크 인터페이스 가져오기
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
        perror("Failed to get interface index");
        close(sock);
        return -1;
    }

    // 소켓 주소 설정
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
        perror("Bind failed");
        close(sock);
        return -1;
    }

	unsigned char packet[64] = { 
    	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // 목적지 MAC (브로드캐스트)
    	0x00, 0x0C, 0x29, 0x6B, 0x1A, 0x0E,  // 출발지 MAC
    	0x08, 0x00,                          // 이더넷 타입 (IPv4)
    	// 페이로드 데이터
	};

	int len = sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&sll, sizeof(sll));
	if (len == -1) {
    	perror("Packet send failed");
	} else {
    	printf("Packet sent successfully\n");
	}


    // 패킷 수신
    printf("Listening for packets...\n");
    while (1) {
        int len = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (len == -1) {
            perror("Packet receive failed");
            break;
        }
        printf("Received packet of length %d\n", len);
    }

    close(sock);
    return 0;
}

