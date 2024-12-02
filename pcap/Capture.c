//
// Packet Capture Example: Analysis of Captured Data
//
// Network Software Design
// Department of Software and Computer Engineering, Ajou University
// by Byeong-hee Roh


//202221106임세현 작성 


#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <stdint.h>

#pragma warning(disable:4996)

#define LINE_LEN 16

// literals related to distinguishing protocols
#define ETHERTYPE_IP        0x0800
#define ETH_II_HSIZE        14      // Ethernet II 헤더 크기
#define IP_PROTO_TCP        6       // TCP
#define IP_PROTO_UDP        17      // UDP

/* 이더넷 헤더 구조체 */
struct ethernet_header {
    uint8_t dest_mac[6];   // 목적지 MAC 주소
    uint8_t src_mac[6];    // 소스 MAC 주소
    uint16_t eth_type;     // Ethernet 타입
};

// IPv4 헤더 구조체
struct ip_header {
    uint8_t  ihl : 4;      // IP 헤더 길이
    uint8_t  version : 4;  // IP 버전
    uint8_t  tos;          // 서비스 타입
    uint16_t tot_len;      // 전체 길이
    uint16_t id;           // 식별자
    uint16_t frag_off;     // 플래그 + 오프셋
    uint8_t  ttl;          // TTL
    uint8_t  protocol;     // 프로토콜 (TCP, UDP 등)
    uint16_t checksum;     // 체크섬
    uint32_t saddr;        // 소스 IP 주소
    uint32_t daddr;        // 목적지 IP 주소
};

// TCP 헤더 구조체
struct tcp_header {
    uint16_t src_port;       // 소스 포트 번호
    uint16_t dst_port;       // 목적지 포트 번호
    uint32_t seq_num;        // 시퀀스 번호
    uint32_t ack_num;        // 응답 번호
    uint16_t hlen_flags;     // 헤더 길이 (4비트) + 예약 (6비트) + 플래그(6비트)
    uint16_t window;         // 윈도우 크기
    uint16_t checksum;       // 체크섬
    uint16_t urg_ptr;        // 긴급 포인터
};

// UDP 헤더 구조체
struct udp_header {
    uint16_t src_port;       // 소스 포트 번호
    uint16_t dst_port;       // 목적지 포트 번호
    uint16_t length;         // UDP 데이터그램 크기
    uint16_t checksum;       // 체크섬
};

// 헬퍼 함수들
uint16_t read_uint16(unsigned char *buffer, int offset, int need_swap) {
    uint16_t value = (buffer[offset] << 8) | buffer[offset + 1];
    if (need_swap) {
        value = (value >> 8) | (value << 8);
    }
    return value;
}

uint32_t read_uint32(unsigned char *buffer, int offset, int need_swap) {
    uint32_t value = (buffer[offset] << 24) | (buffer[offset + 1] << 16) |
                     (buffer[offset + 2] << 8) | buffer[offset + 3];
    if (need_swap) {
        value = ((value >> 24) & 0xff) | ((value >> 8) & 0xff00) |
                ((value << 8) & 0xff0000) | ((value << 24) & 0xff000000);
    }
    return value;
}

int parse_ip_header(unsigned char* data, struct ip_header *ip_hdr)
{
    ip_hdr->version     = data[0] >> 4;         // IP version
    ip_hdr->ihl         = data[0] & 0x0f;       // IP header length
    ip_hdr->tos         = data[1];            
    ip_hdr->tot_len     = ntohs(*(uint16_t*)&data[2]);    //uint16_t*로 캐스팅하여, 2바이트 단위로 접근할 수 있게 한다 
    ip_hdr->id          = ntohs(*(uint16_t*)&data[4]);   
    ip_hdr->frag_off    = ntohs(*(uint16_t*)&data[6]);   
    ip_hdr->ttl         = data[8];              // Time to Live
    ip_hdr->protocol    = data[9];              // Protocol
    ip_hdr->checksum    = ntohs(*(uint16_t*)&data[10]);   
    ip_hdr->saddr       = ntohl(*(uint32_t*)&data[12]);   //4바이트 단위로 접근가능 
    ip_hdr->daddr       = ntohl(*(uint32_t*)&data[16]);   

    return 0;
}

int parse_ethernet_header(unsigned char* data, struct ethernet_header *eth_hdr)
{
    int i;

    for (i = 0; i < 6; i++) {
        eth_hdr->dest_mac[i] = data[i];
    }

    for (i = 0; i < 6; i++) {
        eth_hdr->src_mac[i] = data[i+6];
    }

    // Ethernet type
    eth_hdr->eth_type = ntohs(*(uint16_t*)&data[12]);

    return 0;
}

int parse_tcp_header(unsigned char* data, struct tcp_header* tcp_hdr)
{
    tcp_hdr->src_port   = ntohs(*(uint16_t*)&data[0]);
    tcp_hdr->dst_port   = ntohs(*(uint16_t*)&data[2]);
    tcp_hdr->seq_num    = ntohl(*(uint32_t*)&data[4]);
    tcp_hdr->ack_num    = ntohl(*(uint32_t*)&data[8]);
    tcp_hdr->hlen_flags = ntohs(*(uint16_t*)&data[12]);
    tcp_hdr->window     = ntohs(*(uint16_t*)&data[14]);
    tcp_hdr->checksum   = ntohs(*(uint16_t*)&data[16]);
    tcp_hdr->urg_ptr    = ntohs(*(uint16_t*)&data[18]);

    return 0;
}

int parse_udp_header(unsigned char* data, struct udp_header* udp_hdr)
{
    udp_hdr->src_port   = ntohs(*(uint16_t*)&data[0]);
    udp_hdr->dst_port   = ntohs(*(uint16_t*)&data[2]);
    udp_hdr->length     = ntohs(*(uint16_t*)&data[4]);
    udp_hdr->checksum   = ntohs(*(uint16_t*)&data[6]);

    return 0;
}

int main(int argc, char** argv)
{
    unsigned char           magic_bytes[4];
    unsigned char           pcap_header_rest[20];
    unsigned char           pcap_pk_data[65536];    // 패킷 데이터 버퍼
    FILE*                   fin;
    int                     pk_no, res, offset = 0;
    double                  init_time, curr_time;   // 첫 번째 패킷 캡처 시간, 현재 패킷 캡처 시간
    unsigned long           net_ip_count = 0, net_etc_count = 0;
    unsigned long           trans_tcp_count = 0, trans_udp_count = 0, trans_etc_count = 0;
    int                     continue_flag = 1;
    int                     need_swap = 0;

    // PCAP 파일 열기
    fin = fopen("ccc.pcap", "rb");
    if (fin == NULL) {
        printf("파일을 열 수 없습니다.\n");
        exit(0) ;
    }

    // 매직 넘버 읽기
    if (fread(magic_bytes, 1, 4, fin) != 4) {
        printf("매직 넘버를 읽는 중 오류 발생\n");
        exit(1);
    }

    // 매직 넘버 해석
    uint32_t magic_number = (magic_bytes[0] << 24) | (magic_bytes[1] << 16) | (magic_bytes[2] << 8) | magic_bytes[3];
    uint32_t magic_number_swapped = (magic_bytes[3] << 24) | (magic_bytes[2] << 16) | (magic_bytes[1] << 8) | magic_bytes[0];

    if (magic_number == 0xa1b2c3d4) {
        need_swap = 0; // 동일한 엔디언
    } else if (magic_number_swapped == 0xa1b2c3d4) {
        need_swap = 1; // 엔디언 변환 필요
        magic_number = magic_number_swapped;
    } else {
        printf("지원되지 않는 PCAP 파일 형식 (매직 넘버 불일치)\n");
        exit(1);
    }

    // 나머지 글로벌 헤더 읽기
    if (fread(pcap_header_rest, 1, 20, fin) != 20) {
        printf("PCAP 헤더를 읽는 중 오류 발생\n");
        exit(1);
    }

    // 글로벌 헤더 필드 파싱
    struct pcap_file_header pcap_global_hdr;
    pcap_global_hdr.magic = magic_number;
    pcap_global_hdr.version_major = read_uint16(pcap_header_rest, 0, need_swap);
    pcap_global_hdr.version_minor = read_uint16(pcap_header_rest, 2, need_swap);
    pcap_global_hdr.thiszone = read_uint32(pcap_header_rest, 4, need_swap);
    pcap_global_hdr.sigfigs = read_uint32(pcap_header_rest, 8, need_swap);
    pcap_global_hdr.snaplen = read_uint32(pcap_header_rest, 12, need_swap);
    pcap_global_hdr.linktype = read_uint32(pcap_header_rest, 16, need_swap);

    pk_no = 0;
    while (1) {
        // 패킷 헤더 읽기
        unsigned char pkt_hdr_bytes[16];
        if (fread(pkt_hdr_bytes, 1, 16, fin) != 16)
            break; // EOF 또는 오류

        struct pcap_pkthdr pcap_pk_hdr;
        pcap_pk_hdr.ts.tv_sec = read_uint32(pkt_hdr_bytes, 0, need_swap);
        pcap_pk_hdr.ts.tv_usec = read_uint32(pkt_hdr_bytes, 4, need_swap);
        pcap_pk_hdr.caplen = read_uint32(pkt_hdr_bytes, 8, need_swap);
        pcap_pk_hdr.len = read_uint32(pkt_hdr_bytes, 12, need_swap);

        // 캡처한 시간 구하기
        curr_time = pcap_pk_hdr.ts.tv_sec + pcap_pk_hdr.ts.tv_usec * 0.000001;
        if (pk_no == 0)
            init_time = curr_time;

        // 패킷 데이터 읽기 (버퍼 오버플로우 방지)
        if (pcap_pk_hdr.caplen > sizeof(pcap_pk_data)) {
            printf("패킷이 너무 큽니다.\n");
            break;
        }

        if (fread(pcap_pk_data, 1, pcap_pk_hdr.caplen, fin) != pcap_pk_hdr.caplen) {
            printf("패킷 데이터를 읽는 중 오류 발생\n");
            break;
        }

        // 이더넷 프레임 헤더 분석
        offset = 0;
        struct ethernet_header eth_hdr;
        parse_ethernet_header(&pcap_pk_data[offset], &eth_hdr);

        // 헤더 구조체들을 선언
        struct ip_header ip_hdr;
        struct tcp_header tcp_hdr;
        struct udp_header udp_hdr;

        if (eth_hdr.eth_type == ETHERTYPE_IP) {
            // IP 헤더 분석
            offset += ETH_II_HSIZE;
            parse_ip_header(&pcap_pk_data[offset], &ip_hdr);
            net_ip_count++;

            // IP 주소 엔디언 변환
            ip_hdr.saddr = ntohl(ip_hdr.saddr);
            ip_hdr.daddr = ntohl(ip_hdr.daddr);

            offset += ip_hdr.ihl * 4;  // IP 헤더 길이만큼 이동
            if (ip_hdr.protocol == IP_PROTO_TCP) {
                parse_tcp_header(&pcap_pk_data[offset], &tcp_hdr);
                trans_tcp_count++;
            }
            else if (ip_hdr.protocol == IP_PROTO_UDP) {
                parse_udp_header(&pcap_pk_data[offset], &udp_hdr);
                trans_udp_count++;
            }
            else
                trans_etc_count++;
        }
        else {
            net_etc_count++;
        }

        pk_no++;

        // 실습 1: 패킷 정보 출력
        printf("%-5d %-10.6f %-15s %-15s %-6s %-6d ",
            pk_no,
            curr_time - init_time,
            (eth_hdr.eth_type == ETHERTYPE_IP) ? inet_ntoa(*(struct in_addr*)&ip_hdr.saddr) : "N/A",
            (eth_hdr.eth_type == ETHERTYPE_IP) ? inet_ntoa(*(struct in_addr*)&ip_hdr.daddr) : "N/A",
            (eth_hdr.eth_type == ETHERTYPE_IP) ?
                (ip_hdr.protocol == IP_PROTO_TCP) ? "TCP" :
                (ip_hdr.protocol == IP_PROTO_UDP) ? "UDP" : "ETC" : "NON-IP",
            pcap_pk_hdr.len);

        // Info 필드 구성
        if (eth_hdr.eth_type == ETHERTYPE_IP) {
            if (ip_hdr.protocol == IP_PROTO_TCP) {
                // TCP 플래그 파싱
                uint16_t flags = tcp_hdr.hlen_flags & 0x003F; // 하위 6비트가 플래그
                char flag_str[7] = { '0','0','0','0','0','0','\0' };
                char flag_chars[6] = { 'U', 'A', 'P', 'R', 'S', 'F' };

                for (int i = 0; i < 6; i++) {
                    if (flags & (1 << (5 - i))) {
                        flag_str[i] = flag_chars[i];
                    }
                    else {
                        flag_str[i] = '0';
                    }
                }

                printf(" %d -> %d [Flag: %s]\n",
                    tcp_hdr.src_port,
                    tcp_hdr.dst_port,
                    flag_str);
            }
            else if (ip_hdr.protocol == IP_PROTO_UDP) {
                printf(" %d -> %d\n",
                    udp_hdr.src_port,
                    udp_hdr.dst_port);
            }
            else {
                printf(" protocol = %d\n", ip_hdr.protocol);
            }
        } else {
            printf("\n");
        }

        // 실습 2: 사용자 입력 및 헤더 정보 출력
        if (continue_flag) {
            int user_input;
            printf("Enter 1 to proceed to next packet, 0 to finish: ");
            if (scanf("%d", &user_input) != 1) {
                printf("입력 오류\n");
                break;
            }

            if (user_input == 0) {
                // 남은 패킷에 대해 실습 1의 내용만 출력하면서 끝까지 진행
                continue_flag = 0;
            }
            else {
                // 헤더 필드 정보 출력
                printf("=== Ethernet Header ===\n");
                printf("Src MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                    eth_hdr.src_mac[0], eth_hdr.src_mac[1], eth_hdr.src_mac[2],
                    eth_hdr.src_mac[3], eth_hdr.src_mac[4], eth_hdr.src_mac[5]);
                printf("Dst MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                    eth_hdr.dest_mac[0], eth_hdr.dest_mac[1], eth_hdr.dest_mac[2],
                    eth_hdr.dest_mac[3], eth_hdr.dest_mac[4], eth_hdr.dest_mac[5]);

                if (eth_hdr.eth_type == ETHERTYPE_IP) {
                    printf("=== IP Header ===\n");
                    printf("Version: %d\n", ip_hdr.version);
                    printf("IHL: %d\n", ip_hdr.ihl);
                    printf("Type of Service: %d\n", ip_hdr.tos);
                    printf("Total Length: %d\n", ip_hdr.tot_len);
                    printf("Identification: %d\n", ip_hdr.id);
                    printf("Fragment Offset: %d\n", ip_hdr.frag_off);
                    printf("TTL: %d\n", ip_hdr.ttl);
                    printf("Protocol: %d\n", ip_hdr.protocol);
                    printf("Checksum: %d\n", ip_hdr.checksum);
                    printf("Source IP: %s\n", inet_ntoa(*(struct in_addr*)&ip_hdr.saddr));
                    printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr*)&ip_hdr.daddr));

                    if (ip_hdr.protocol == IP_PROTO_TCP) {
                        printf("=== TCP Header ===\n");
                        printf("Source Port: %d\n", tcp_hdr.src_port);
                        printf("Destination Port: %d\n", tcp_hdr.dst_port);
                        printf("Sequence Number: %u\n", tcp_hdr.seq_num);
                        printf("Acknowledgment Number: %u\n", tcp_hdr.ack_num);
                        printf("Header Length & Flags: %04X\n", tcp_hdr.hlen_flags);
                        printf("Window Size: %d\n", tcp_hdr.window);
                        printf("Checksum: %d\n", tcp_hdr.checksum);
                        printf("Urgent Pointer: %d\n", tcp_hdr.urg_ptr);
                    }
                    else if (ip_hdr.protocol == IP_PROTO_UDP) {
                        printf("=== UDP Header ===\n");
                        printf("Source Port: %d\n", udp_hdr.src_port);
                        printf("Destination Port: %d\n", udp_hdr.dst_port);
                        printf("Length: %d\n", udp_hdr.length);
                        printf("Checksum: %d\n", udp_hdr.checksum);
                    }
                }
            }
        }
    }

    fclose(fin);

    // 통계 정보 출력
    printf("#total number of packets : %d\n", pk_no);
    printf("IP packets: %lu\n", net_ip_count);
    printf("non-IP packets: %lu\n", net_etc_count);
    printf("TCP packets: %lu\n", trans_tcp_count);
    printf("UDP packets: %lu\n", trans_udp_count);

    return 0;
}
