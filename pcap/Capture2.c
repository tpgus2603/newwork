//
// Packet Capture Example: Analysis of Captured Data
//
// Network Software Design
// Department of Software and Computer Engineering, Ajou University
// by Byeong-hee Roh
//

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#pragma warning(disable:4996)

#define LINE_LEN 16

// litereals realted to distinguishing protocols
#define ETHERTYPE_IP		0x0800
#define ETH_II_HSIZE		14		// EthernetII 헤더 크기
#define IP_HSIZE		20		// IP 헤더 크기 (옵션 없음)
#define IP_PROTO_TCP		6		// TCP
#define IP_PROTO_UDP		17		// UDP

// modified packet header
struct pcap_pkthdr_modified {
    unsigned int ts_sec;
    unsigned int ts_usec;
    unsigned int caplen;
    unsigned int len;
};

// etherent header
struct ethernet_header {
	uint8_t dest_mac[6];   // 목적지 MAC 주소
	uint8_t src_mac[6];    // 소스 MAC 주소
	uint16_t eth_type;     // Ethernet 타입
};

// IPv4 Header
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

// TCP Header
struct tcp_header {
	uint16_t src_port;       // 소스 포트 번호
	uint16_t dst_port;       // 목적지 포트 번호
	uint32_t seq_num;        // 시퀀스 번호
	uint32_t ack_num;        // 응답 번호
	uint16_t hlen_flags;     // 헤더길이 (4비트) + Unused (6비트) + 플래그(6비트)
	uint16_t window;         // 윈도우 크기
	uint16_t checksum;       // 체크섬
	uint16_t urg_ptr;        // 긴급포인터
};

// UDP Header
struct udp_header {
	uint16_t src_port;       // 소스 포트 번호
	uint16_t dst_port;       // 목적지 포트 번호
	uint16_t length;         // UDP 데이터그램 크기
	uint16_t checksum;       // 체크섬
};

struct ethernet_header	eth_hdr;
struct ip_header	ip_hdr;
struct tcp_header	tcp_hdr;
struct udp_header	udp_hdr;

// Macros
// pntohs : to convert network-aligned 16bit word to host-aligned one
#define pntoh16(p)  ((unsigned short)                       \
                    ((unsigned short)*((unsigned char *)(p)+0)<<8|  \
                     (unsigned short)*((unsigned char *)(p)+1)<<0))

// pntohl : to convert network-aligned 32bit word to host-aligned one
#define pntoh32(p)  ((unsigned short)*((unsigned char *)(p)+0)<<24|  \
                    (unsigned short)*((unsigned char *)(p)+1)<<16|  \
                    (unsigned short)*((unsigned char *)(p)+2)<<8|   \
                    (unsigned short)*((unsigned char *)(p)+3)<<0)

int parse_ip_header(unsigned char* data, struct ip_header *ip_hdr)
{
	ip_hdr->version		= data[0] >> 4;		// IP version
	ip_hdr->ihl		= data[0] & 0x0f;	// IP header length
	ip_hdr->protocol	= data[9];		    // protocol above IP
	// 실습: 여기에 다른 IP 헤더 필드 정보 추가

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

	// ethernet type check
	eth_hdr->eth_type = pntoh16(&data[12]);

	return 0;
}

int parse_tcp_header(unsigned char* data, struct tcp_header* tcp_hdr)
{
	tcp_hdr->src_port	= pntoh16(&data[0]);
	tcp_hdr->dst_port	= pntoh16(&data[2]);
	tcp_hdr->seq_num	= pntoh32(&data[4]);
	tcp_hdr->ack_num	= pntoh32(&data[8]);
	tcp_hdr->hlen_flags 	= pntoh16(&data[12]);
	tcp_hdr->window		= pntoh16(&data[14]);
	tcp_hdr->checksum	= pntoh16(&data[16]);
	tcp_hdr->urg_ptr	= pntoh16(&data[18]);

	return 0;
}

int parse_udp_header(unsigned char* data, struct udp_header* udp_hdr)
{
	udp_hdr->src_port	= pntoh16(&data[0]);
	udp_hdr->dst_port	= pntoh16(&data[2]);
	udp_hdr->length		= pntoh16(&data[4]);
	udp_hdr->checksum	= pntoh16(&data[6]);

	return 0;
}

void main(int argc, char** argv)
{
	struct pcap_file_header	pcap_global_hdr;		// PCAP 글로벌 헤더
	//struct pcap_pkthdr 		pcap_pk_hdr;			// PCAP 패킷 헤더
	struct pcap_pkthdr_modified	pcap_pk_hdr;
	unsigned char			pcap_pk_data[2000];		// PCAP 패킷 데이터
	FILE*			fin;
	int			pk_no, res, offset=0;
	double			init_time, curr_time;	// 첫번째 패킷 캡쳐 시간, 현재 패킷 캡쳐 시간
	int			net_ip_count=0, net_etc_count=0;
	int			trans_tcp_count=0, trans_udp_count=0, trans_etc_count=0;

	// PCAP 파일 열기
	fin = fopen("ccc.pcap", "rb");
	//printf("global=%d\n", (int)sizeof(pcap_global_hdr));
	//printf("pkt=%d\n", (int)sizeof(pcap_pk_hdr));

	// 글로벌 헤더 읽기
	fread((char*)&pcap_global_hdr, sizeof(pcap_global_hdr), 1, fin);
	if (pcap_global_hdr.magic != 0xA1B2C3D4) {
		printf("파일 오류: 지원되지 않는 PCAP 파일 형식 (0x%x)\n", pcap_global_hdr.magic);
		exit(0);
	}

	pk_no = 0;
	while (1) {

		// 패킷 헤더 읽기
		if (fread((char*)&pcap_pk_hdr, sizeof(pcap_pk_hdr), 1, fin) == 0)
			break;
		
		// 캡쳐한 시간 구하기
		//curr_time = pcap_pk_hdr.ts.tv_sec + pcap_pk_hdr.ts.tv_usec * 0.000001;
		curr_time = pcap_pk_hdr.ts_sec + pcap_pk_hdr.ts_usec * 0.000001;
		if (pk_no == 0)
			init_time = curr_time;

		// 패킷 헤더에 지정된 크기 (caplen)의 캡쳐된 데이터 읽기
		fread(pcap_pk_data, sizeof(unsigned char), pcap_pk_hdr.caplen, fin);

		// 이더넷 프레임 헤더 분석
		offset = 0;
		res = parse_ethernet_header(&pcap_pk_data[offset], &eth_hdr);

		if (eth_hdr.eth_type == ETHERTYPE_IP) {
			// IP 헤더 분석
			offset += ETH_II_HSIZE;
			res = parse_ip_header(&pcap_pk_data[offset], &ip_hdr);
			net_ip_count++;

			offset += IP_HSIZE;
			if (ip_hdr.protocol == IP_PROTO_TCP) {
				res = parse_tcp_header(&pcap_pk_data[offset], &tcp_hdr);
				trans_tcp_count++;
			}
			else if (ip_hdr.protocol == IP_PROTO_UDP) {
				res = parse_udp_header(&pcap_pk_data[offset], &udp_hdr);
				trans_udp_count++;
			}
			else
				trans_etc_count++;
		}
		else
			net_etc_count++;

		pk_no++;

		// 실습 1: 여기에 wireshark과 같이 No | Time | Source | Destination | Protocol | Length | Info 가 나오도록 prinft 문 작성
		// 실습 2: 여기에 wireshark과 같이 Ethernet, IP, TCP 또는 UDP 헤더 필드 정보들을 표현하는 printf 문 작성
		//         입력을 받도록 하고, 입력이 <1>이면 다음 패킷으로 진행, <0>이면 실습 1의 내용만 보이면서 끝까지 진행 

	}
	fclose(fin);

	printf("#total number of packets : %d\n", pk_no);
	printf("IP packets: %d\n", net_ip_count);
	printf("non-IP packets: %d\n", net_etc_count);
	printf("TCP packets: %d\n", trans_tcp_count);
	printf("UDP packets: %d\n", trans_udp_count);
}
