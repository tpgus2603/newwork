#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>      // IPv6 헤더 정의
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>  // ICMP 헤더 정의
#include <net/ethernet.h>
#include <sys/time.h>
#include <time.h>

/* 상수 정의 */
#define DEFAULT_SNAPLEN 65535
#define DEFAULT_FILTER "ip"
#define DEFAULT_PACKET_COUNT 1000
#define DEFAULT_TIMEOUT 10  // 초
#define BUFFER_TIMEOUT_MS 100  // 패킷 버퍼 타임아웃 (밀리초)


pcap_t *adhandle = NULL;        // 패킷 캡처 핸들러
pcap_dumper_t *dumpfile = NULL;

/* 캡처 통계 구조체 */
typedef struct {
    int captured_packets;
    unsigned long ip_packets;
    unsigned long ipv6_packets;  // IPv6 패킷 수 추가
    unsigned long non_ip_packets;
    unsigned long tcp_packets;
    unsigned long udp_packets;
} capture_stats_t;

capture_stats_t stats = {0};

/* 사용자 데이터 구조체 */
typedef struct {
    pcap_dumper_t *dumpfile;
    struct timeval start_time;
    int is_first_packet;
    double timeout_seconds;
} user_data_t;


void timeval_diff(struct timeval *result, struct timeval *x, struct timeval *y) {
    result->tv_sec = x->tv_sec - y->tv_sec;
    result->tv_usec = x->tv_usec - y->tv_usec;
    if (result->tv_usec < 0) {
        --result->tv_sec;
        result->tv_usec += 1000000;
    }
}
//패킷캡쳐 함수 
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    user_data_t *data = (user_data_t *)user;
    stats.captured_packets++;

    /* 패킷 번호 */
    int packet_no = stats.captured_packets;

    /* 패킷 캡처 시간 계산 */
    struct timeval elapsed;
    if (data->is_first_packet) {
        data->start_time = header->ts;
        data->is_first_packet = 0;
        elapsed.tv_sec = 0;
        elapsed.tv_usec = 0;
    } else {
        timeval_diff(&elapsed, &header->ts, &data->start_time);
    }

    
    double elapsed_time = elapsed.tv_sec + elapsed.tv_usec / 1000000.0;

    /* Ethernet 헤더 */
    struct ether_header *eth_header = (struct ether_header *)packet;
    int eth_header_len = sizeof(struct ether_header);
    uint16_t ether_type = ntohs(eth_header->ether_type);

    /* VLAN 태깅 처리 (802.1Q 또는 802.1ad) */
    while (ether_type == 0x8100 || ether_type == 0x88a8) { // 0x8100: 802.1Q, 0x88a8: 802.1ad
        /* VLAN 태그가 있으면 다음 4바이트를 건너뜀 */
        eth_header_len += 4;
        if (header->caplen < eth_header_len + 2) {
            printf("| %-5d | %-8.3f | %-39s | %-39s | %-7s | %-6d | %-30s |\n",
                   packet_no, elapsed_time, "N/A", "N/A", "Malformed", header->len, "N/A");
            stats.non_ip_packets++;
            return;
        }
        ether_type = ntohs(*(uint16_t *)(packet + eth_header_len - 2));
    }

    char src_ip[INET6_ADDRSTRLEN] = "N/A";
    char dst_ip[INET6_ADDRSTRLEN] = "N/A";
    char protocol[16] = "N/A";
    char info[256] = "N/A";


    if (ether_type == ETHERTYPE_IP) {
        /* IPv4 패킷 처리 */
        struct ip *ip_header = (struct ip *)(packet + eth_header_len);
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, sizeof(dst_ip));

        /* 프로토콜 확인 */
        switch (ip_header->ip_p) {
            case IPPROTO_TCP: {
                strncpy(protocol, "TCP", sizeof(protocol));
                struct tcphdr *tcp_header = (struct tcphdr *)(packet + eth_header_len + ip_header->ip_hl * 4);
                snprintf(info, sizeof(info), "Src Port: %d, Dst Port: %d",
                         ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport));
                stats.tcp_packets++;
                break;
            }
            case IPPROTO_UDP: {
                strncpy(protocol, "UDP", sizeof(protocol));
                struct udphdr *udp_header = (struct udphdr *)(packet + eth_header_len + ip_header->ip_hl * 4);
                snprintf(info, sizeof(info), "Src Port: %d, Dst Port: %d",
                         ntohs(udp_header->uh_sport), ntohs(udp_header->uh_dport));
                stats.udp_packets++;
                break;
            }
            case IPPROTO_ICMP: {
                strncpy(protocol, "ICMP", sizeof(protocol));
                struct icmphdr *icmp_header = (struct icmphdr *)(packet + eth_header_len + ip_header->ip_hl * 4);
                snprintf(info, sizeof(info), "Type: %d, Code: %d",
                         icmp_header->type, icmp_header->code);
                break;
            }
            default: {
                snprintf(protocol, sizeof(protocol), "OTHER (%d)", ip_header->ip_p);
                break;
            }
        }

    
        stats.ip_packets++;
    } else if (ether_type == ETHERTYPE_IPV6) {
        /* IPv6 패킷 처리 */
        struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet + eth_header_len);
        inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip, sizeof(src_ip));
        inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip, sizeof(dst_ip));

        uint8_t next_header = ip6_header->ip6_nxt;

        if (next_header == IPPROTO_TCP) {
            strncpy(protocol, "TCP", sizeof(protocol));
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + eth_header_len + sizeof(struct ip6_hdr));
            snprintf(info, sizeof(info), "Src Port: %d, Dst Port: %d",
                     ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport));
            stats.tcp_packets++;
        } else if (next_header == IPPROTO_UDP) {
            strncpy(protocol, "UDP", sizeof(protocol));
            struct udphdr *udp_header = (struct udphdr *)(packet + eth_header_len + sizeof(struct ip6_hdr));
            snprintf(info, sizeof(info), "Src Port: %d, Dst Port: %d",
                     ntohs(udp_header->uh_sport), ntohs(udp_header->uh_dport));
            stats.udp_packets++;
        } else if (next_header == IPPROTO_ICMPV6) {
            strncpy(protocol, "ICMPv6", sizeof(protocol));
        } else {
            snprintf(protocol, sizeof(protocol), "OTHER (%d)", next_header);
        }

        /* IPv6 패킷 카운트 */
        stats.ipv6_packets++;
    } else {
        /* 비-IP 패킷일 경우 */
        strncpy(protocol, "Non-IP", sizeof(protocol));
        stats.non_ip_packets++;
    }

    /* 패킷 정보 출력 */
    printf("| %-5d | %-8.3f | %-39s | %-39s | %-7s | %-6d | %-30s |\n",
           packet_no, elapsed_time, src_ip, dst_ip, protocol, header->len, info);/
    pcap_dump((u_char *)data->dumpfile, header, packet);
}

/* 사용 가능한 네트워크 장치를 나열하는 함수 */
void list_devices() {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0;

    /* 장치 목록 검색 */
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs 오류: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    /* 목록 출력 */
    printf("사용 가능한 네트워크 장치:\n");
    for (d = alldevs; d != NULL; d = d->next) {
        printf("[%d] %s", ++i, d->name);
        if (d->description)
            printf(" - %s", d->description);
        else
            printf(" - 설명 없음");

        /* IP 주소 출력 */
        pcap_addr_t *a;
        for (a = d->addresses; a != NULL; a = a->next) {
            if (a->addr->sa_family == AF_INET) { // IPv4
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &((struct sockaddr_in *)a->addr)->sin_addr, ip, sizeof(ip));
                printf(" [IP: %s]", ip);
            } else if (a->addr->sa_family == AF_INET6) { // IPv6
                char ip6[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &((struct sockaddr_in6 *)a->addr)->sin6_addr, ip6, sizeof(ip6));
                printf(" [IPv6: %s]", ip6);
            }
        }
        printf("\n");
    }

    if (i == 0) {
        printf("\n인터페이스를 찾을 수 없습니다! libpcap이 설치되었는지 확인하세요.\n");
        pcap_freealldevs(alldevs);
        exit(EXIT_FAILURE);
    }

    pcap_freealldevs(alldevs);
}

/* 패킷 분석을 위한 구조체 */
typedef struct {
    int total_packets;
    struct pcap_pkthdr *headers;
    const u_char **packets;
} analysis_data_t;

/* 패킷 분석 함수 */
int analyze_pcap_file(const char *filename, analysis_data_t *data) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const u_char *packet;
    struct pcap_pkthdr header;
    int packet_count = 0;
    int capacity = 1000;

    /* pcap 파일 열기 */
    handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_offline 오류: %s\n", errbuf);
        return -1;
    }

    /* 메모리 할당 */
    data->headers = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr) * capacity);
    data->packets = (const u_char **)malloc(sizeof(u_char *) * capacity);
    if (data->headers == NULL || data->packets == NULL) {
        fprintf(stderr, "메모리 할당 실패\n");
        pcap_close(handle);
        return -1;
    }

    /* 패킷 읽기 */
    while ((packet = pcap_next(handle, &header)) != NULL) {
        if (packet_count >= capacity) {
            capacity *= 2;
            data->headers = (struct pcap_pkthdr *)realloc(data->headers, sizeof(struct pcap_pkthdr) * capacity);
            data->packets = (const u_char **)realloc(data->packets, sizeof(u_char *) * capacity);
            if (data->headers == NULL || data->packets == NULL) {
                fprintf(stderr, "메모리 재할당 실패\n");
                pcap_close(handle);
                return -1;
            }
        }
        data->headers[packet_count] = header;

        /* 패킷 데이터를 별도의 메모리에 복사 */
        u_char *packet_copy = (u_char *)malloc(header.caplen);
        if (packet_copy == NULL) {
            fprintf(stderr, "패킷 복사 실패\n");
            pcap_close(handle);
            return -1;
        }
        memcpy(packet_copy, packet, header.caplen);
        data->packets[packet_count] = packet_copy;
        packet_count++;
    }

    data->total_packets = packet_count;

    pcap_close(handle);
    return 0;
}

/* 패킷 상세 정보 출력 함수 */
void print_packet_details(int packet_no, analysis_data_t *data) {
    if (packet_no < 1 || packet_no > data->total_packets) {
        printf("유효하지 않은 패킷 번호입니다.\n");
        return;
    }

    int index = packet_no - 1;
    struct pcap_pkthdr header = data->headers[index];
    const u_char *packet = data->packets[index];

    /* Ethernet 헤더 */
    struct ether_header *eth_header = (struct ether_header *)packet;
    printf("=== Ethernet Header ===\n");
    printf("Src MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth_header->ether_shost[0],
           eth_header->ether_shost[1],
           eth_header->ether_shost[2],
           eth_header->ether_shost[3],
           eth_header->ether_shost[4],
           eth_header->ether_shost[5]);
    printf("Dst MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth_header->ether_dhost[0],
           eth_header->ether_dhost[1],
           eth_header->ether_dhost[2],
           eth_header->ether_dhost[3],
           eth_header->ether_dhost[4],
           eth_header->ether_dhost[5]);

    uint16_t ether_type = ntohs(eth_header->ether_type);
    int eth_header_len = sizeof(struct ether_header);

    /* VLAN 태그 처리 */
    while (ether_type == 0x8100 || ether_type == 0x88a8) {
        eth_header_len += 4;
        ether_type = ntohs(*(uint16_t *)(packet + eth_header_len - 2));
    }

    /* IP 헤더 확인 */
    if (ether_type == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + eth_header_len);
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, sizeof(dst_ip));

        printf("=== IP Header ===\n");
        printf("Version: %d\n", ip_header->ip_v);
        printf("IHL: %d\n", ip_header->ip_hl);
        printf("Type of Service: %d\n", ip_header->ip_tos);
        printf("Total Length: %d\n", ntohs(ip_header->ip_len));
        printf("Identification: %d\n", ntohs(ip_header->ip_id));
        printf("Fragment Offset: %d\n", ntohs(ip_header->ip_off));
        printf("TTL: %d\n", ip_header->ip_ttl);
        printf("Protocol: %d\n", ip_header->ip_p);
        printf("Checksum: %d\n", ntohs(ip_header->ip_sum));
        printf("Source IP: %s\n", src_ip);
        printf("Destination IP: %s\n", dst_ip);

        /* 프로토콜별 헤더 분석 */
        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + eth_header_len + ip_header->ip_hl * 4);
            printf("=== TCP Header ===\n");
            printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
            printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));
            printf("Sequence Number: %u\n", ntohl(tcp_header->th_seq));
            printf("Acknowledgment Number: %u\n", ntohl(tcp_header->th_ack));
            printf("Header Length: %d\n", tcp_header->th_off);
            printf("Flags: ");
            if (tcp_header->th_flags & TH_FIN) printf("FIN ");
            if (tcp_header->th_flags & TH_SYN) printf("SYN ");
            if (tcp_header->th_flags & TH_RST) printf("RST ");
            if (tcp_header->th_flags & TH_PUSH) printf("PUSH ");
            if (tcp_header->th_flags & TH_ACK) printf("ACK ");
            if (tcp_header->th_flags & TH_URG) printf("URG ");
            printf("\n");
            printf("Window Size: %d\n", ntohs(tcp_header->th_win));
            printf("Checksum: %d\n", ntohs(tcp_header->th_sum));
            printf("Urgent Pointer: %d\n", ntohs(tcp_header->th_urp));
        }
        else if (ip_header->ip_p == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr *)(packet + eth_header_len + ip_header->ip_hl * 4);
            printf("=== UDP Header ===\n");
            printf("Source Port: %d\n", ntohs(udp_header->uh_sport));
            printf("Destination Port: %d\n", ntohs(udp_header->uh_dport));
            printf("Length: %d\n", ntohs(udp_header->uh_ulen));
            printf("Checksum: %d\n", ntohs(udp_header->uh_sum));
        }
        else if (ip_header->ip_p == IPPROTO_ICMP) {
            struct icmphdr *icmp_header = (struct icmphdr *)(packet + eth_header_len + ip_header->ip_hl * 4);
            printf("=== ICMP Header ===\n");
            printf("Type: %d\n", icmp_header->type);
            printf("Code: %d\n", icmp_header->code);
            printf("Checksum: %d\n", ntohs(icmp_header->checksum));
        }
        else {
            printf("=== Unsupported Protocol ===\n");
        }
    }
    else if (ether_type == ETHERTYPE_IPV6) {
        struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet + eth_header_len);
        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip, sizeof(src_ip));
        inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip, sizeof(dst_ip));

        printf("=== IPv6 Header ===\n");
        printf("Version: %d\n", (ntohl(ip6_header->ip6_flow) >> 28) & 0xF);
        printf("Traffic Class: %d\n", (ntohl(ip6_header->ip6_flow) >> 20) & 0xFF);
        printf("Flow Label: %d\n", ntohl(ip6_header->ip6_flow) & 0xFFFFF);
        printf("Payload Length: %d\n", ntohs(ip6_header->ip6_plen));
        printf("Next Header: %d\n", ip6_header->ip6_nxt);
        printf("Hop Limit: %d\n", ip6_header->ip6_hlim);
        printf("Source IP: %s\n", src_ip);
        printf("Destination IP: %s\n", dst_ip);
    }
    else {
        printf("Non-IP packet. 상세 정보는 지원되지 않습니다.\n");
    }
}

/* 패킷 분석 함수 */
void analyze_packets(const char *filename) {
    analysis_data_t analysis_data;
    if (analyze_pcap_file(filename, &analysis_data) != 0) {
        fprintf(stderr, "패킷 분석 실패\n");
        return;
    }

    if (analysis_data.total_packets == 0) {
        printf("캡처된 패킷이 없습니다.\n");
        free(analysis_data.headers);
        free(analysis_data.packets);
        return;
    }

    printf("\n=== 패킷 분석을 시작합니다 ===\n");
    printf("총 패킷 수: %d\n", analysis_data.total_packets);

    int current_packet = 1;
    int continue_flag = 1;

    while (continue_flag && current_packet <= analysis_data.total_packets) {
        print_packet_details(current_packet, &analysis_data);

        /* 기본 정보 내역 출력 */
        printf("=== 기본 정보 ===\n");
        printf("패킷 번호: %d\n", current_packet);
        struct pcap_pkthdr header = analysis_data.headers[current_packet - 1];
        printf("캡처 시간: %ld.%06ld\n", header.ts.tv_sec, header.ts.tv_usec);
        printf("패킷 길이: %d\n", header.len);

        /* 사용자 입력 처리 */
        printf("\n옵션:\n");
        printf("1 - 다음 패킷으로 진행\n");
        printf("0 - 분석 종료\n");
        printf("특정 패킷 번호 입력 - 해당 패킷으로 이동\n");
        printf("입력: ");

        char input[100];
        if (fgets(input, sizeof(input), stdin) == NULL) {
            printf("입력 오류. 분석을 종료합니다.\n");
            break;
        }

        /* 개행 문자 제거 */
        size_t len = strlen(input);
        if (len > 0 && input[len - 1] == '\n') {
            input[len - 1] = '\0';
        }

        if (strcmp(input, "0") == 0) {
            continue_flag = 0;
            break;
        }
        else if (strcmp(input, "1") == 0) {
            current_packet++;
            if (current_packet > analysis_data.total_packets) {
                printf("더 이상 패킷이 없습니다.\n");
                break;
            }
        }
        else {
            /* 특정 번호 입력 처리 */
            char *endptr;
            long pkt_no = strtol(input, &endptr, 10);
            if (endptr != input && *endptr == '\0' && pkt_no >= 1 && pkt_no <= analysis_data.total_packets) {
                current_packet = (int)pkt_no;
            }
            else {
                printf("유효하지 않은 입력입니다. 다시 시도해주세요.\n");
            }
        }
    }

    printf("\n=== 패킷 분석 종료 ===\n");
    printf("총 패킷 수: %d\n", analysis_data.total_packets);

    /* 메모리 해제 */
    for (int i = 0; i < analysis_data.total_packets; i++) {
        free((void *)analysis_data.packets[i]);
    }
    free(analysis_data.headers);
    free(analysis_data.packets);
}

int main() {
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0;
    int dev_num;
    char *dev_selected = NULL;
    char output_file[256];
    int num_packets = DEFAULT_PACKET_COUNT;  // 패킷 수 기본값
    double timeout_seconds = DEFAULT_TIMEOUT;  // 타임아웃 기본값
    char filter_exp[256] = DEFAULT_FILTER;
    struct bpf_program fp;
    bpf_u_int32 net;
    bpf_u_int32 mask;

    /* 사용 가능한 장치 목록 표시 */
    list_devices();

    /* 장치 목록 검색 */
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs 오류: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    /* 장치 수 세기 */
    for (d = alldevs; d != NULL; d = d->next) {
        i++;
    }

    if (i == 0) {
        printf("인터페이스를 찾을 수 없습니다! libpcap이 설치되었는지 확인하세요.\n");
        pcap_freealldevs(alldevs);
        return EXIT_FAILURE;
    }

    /* 사용자에게 장치 선택을 요청 */
    printf("\n패킷을 캡처할 인터페이스 번호를 입력하세요 (1-%d): ", i);
    char input_buffer[100];
    if (fgets(input_buffer, sizeof(input_buffer), stdin) != NULL) {
        /* 입력 끝의 개행 문자 제거 */
        size_t len = strlen(input_buffer);
        if (len > 0 && input_buffer[len - 1] == '\n') {
            input_buffer[len - 1] = '\0';
        }

        /* 숫자로 변환 */
        char *endptr;
        dev_num = strtol(input_buffer, &endptr, 10);
        if (endptr == input_buffer || *endptr != '\0' || dev_num < 1 || dev_num > i) {
            printf("잘못된 인터페이스 번호입니다.\n");
            pcap_freealldevs(alldevs);
            return EXIT_FAILURE;
        }
    } else {
        printf("입력 오류입니다.\n");
        pcap_freealldevs(alldevs);
        return EXIT_FAILURE;
    }

    /* 선택한 장치로 이동 */
    for (d = alldevs, i = 1; i < dev_num && d != NULL; d = d->next, i++);
    dev_selected = d->name;
    printf("\n선택된 장치: %s\n", dev_selected);

    /* 출력 파일 이름 입력 받기 */
    printf("캡처된 패킷을 저장할 출력 파일 이름을 입력하세요 (예: capture.pcap): ");
    if (fgets(output_file, sizeof(output_file), stdin) != NULL) {
        /* 개행 문자 제거 */
        size_t len = strlen(output_file);
        if (len > 0 && output_file[len - 1] == '\n') {
            output_file[len - 1] = '\0';
        }

        if (strlen(output_file) == 0) {
            printf("출력 파일 이름이 비어있습니다. 기본 파일 이름 'capture.pcap'을 사용합니다.\n");
            strcpy(output_file, "capture.pcap");
        }
    } else {
        printf("입력 오류입니다. 기본 파일 이름 'capture.pcap'을 사용합니다.\n");
        strcpy(output_file, "capture.pcap");
    }

    /* 캡처할 패킷 수 입력 받기 */
    printf("캡처할 패킷 수를 입력하세요 (기본 %d개): ", DEFAULT_PACKET_COUNT);
    if (fgets(input_buffer, sizeof(input_buffer), stdin) != NULL) {
        /* 개행 문자 제거 */
        size_t len = strlen(input_buffer);
        if (len > 0 && input_buffer[len - 1] == '\n') {
            input_buffer[len - 1] = '\0';
        }

        if (strlen(input_buffer) != 0) {
            /* 숫자로 변환 */
            char *endptr;
            long temp_num = strtol(input_buffer, &endptr, 10);
            if (endptr != input_buffer && *endptr == '\0' && temp_num > 0) {
                num_packets = (int)temp_num;
            } else {
                printf("패킷 수가 유효하지 않습니다. 기본값 %d개를 사용합니다.\n", DEFAULT_PACKET_COUNT);
            }
        } else {
            printf("패킷 수가 입력되지 않았습니다. 기본값 %d개를 사용합니다.\n", DEFAULT_PACKET_COUNT);
        }
    } else {
        printf("입력 오류입니다. 기본값 %d개를 사용합니다.\n", DEFAULT_PACKET_COUNT);
    }

    /* 캡처 타임아웃 입력 받기 */
    printf("캡처 타임아웃을 입력하세요 (초, 기본 %d초): ", DEFAULT_TIMEOUT);
    if (fgets(input_buffer, sizeof(input_buffer), stdin) != NULL) {
        /* 개행 문자 제거 */
        size_t len = strlen(input_buffer);
        if (len > 0 && input_buffer[len - 1] == '\n') {
            input_buffer[len - 1] = '\0';
        }

        if (strlen(input_buffer) != 0) {
            /* 숫자로 변환 */
            char *endptr;
            double temp_timeout = strtod(input_buffer, &endptr);
            if (endptr != input_buffer && *endptr == '\0' && temp_timeout > 0) {
                timeout_seconds = temp_timeout;
            } else {
                printf("타임아웃이 유효하지 않습니다. 기본값 %d초를 사용합니다.\n", DEFAULT_TIMEOUT);
            }
        } else {
            printf("타임아웃이 입력되지 않았습니다. 기본값 %d초를 사용합니다.\n", DEFAULT_TIMEOUT);
        }
    } else {
        printf("입력 오류입니다. 기본값 %d초를 사용합니다.\n", DEFAULT_TIMEOUT);
    }

    /* 패킷 필터 입력 받기 */
    printf("패킷 필터를 입력하세요 (기본 '%s'): ", DEFAULT_FILTER);
    if (fgets(filter_exp, sizeof(filter_exp), stdin) != NULL) {
        /* 개행 문자 제거 */
        size_t len = strlen(filter_exp);
        if (len > 0 && filter_exp[len - 1] == '\n') {
            filter_exp[len - 1] = '\0';
        }

        if (strlen(filter_exp) == 0) {
            strcpy(filter_exp, DEFAULT_FILTER);
        }
    } else {
        printf("입력 오류입니다. 기본 필터 '%s'를 사용합니다.\n", DEFAULT_FILTER);
        strcpy(filter_exp, DEFAULT_FILTER);
    }

    /* 네트워크 정보 가져오기 */
    if (pcap_lookupnet(dev_selected, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "네트워크 정보를 가져올 수 없습니다: %s\n", errbuf);
        net = 0;
        mask = PCAP_NETMASK_UNKNOWN; // 네트워크 마스크를 알 수 없을 때 설정
    }

    /* 패킷 캡처를 위해 장치 열기 */
    int read_timeout_ms = (int)(timeout_seconds * 1000); // 사용자가 입력한 초를 밀리초로 변환
    adhandle = pcap_open_live(dev_selected, DEFAULT_SNAPLEN, 1, read_timeout_ms, errbuf); // 타임아웃 설정
    if (adhandle == NULL) {
        fprintf(stderr, "어댑터 %s을(를) 열 수 없습니다: %s\n", dev_selected, errbuf);
        pcap_freealldevs(alldevs);
        return EXIT_FAILURE;
    }

    /* 링크 계층 확인. Ethernet만 지원 */
    if (pcap_datalink(adhandle) != DLT_EN10MB) {
        fprintf(stderr, "장치 %s은(는) Ethernet 헤더를 제공하지 않으므로 지원되지 않습니다.\n", dev_selected);
        pcap_close(adhandle);
        pcap_freealldevs(alldevs);
        return EXIT_FAILURE;
    }

    /* 필터 컴파일 */
    if (pcap_compile(adhandle, &fp, filter_exp, 1, mask) == -1) { 
        fprintf(stderr, "필터 '%s' 컴파일 오류: %s\n", filter_exp, pcap_geterr(adhandle));
        pcap_close(adhandle);
        pcap_freealldevs(alldevs);
        return EXIT_FAILURE;
    }

    /* 필터 적용 */
    if (pcap_setfilter(adhandle, &fp) == -1) {
        fprintf(stderr, "필터 '%s' 적용 오류: %s\n", filter_exp, pcap_geterr(adhandle));
        pcap_freecode(&fp);
        pcap_close(adhandle);
        pcap_freealldevs(alldevs);
        return EXIT_FAILURE;
    }

    pcap_freecode(&fp);

    /* 덤프 파일 열기 */
    dumpfile = pcap_dump_open(adhandle, output_file);
    if (dumpfile == NULL) {
        fprintf(stderr, "출력 파일 '%s' 열기 오류: %s\n", output_file, pcap_geterr(adhandle));
        pcap_close(adhandle);
        pcap_freealldevs(alldevs);
        return EXIT_FAILURE;
    }

    /* 사용자 데이터 초기화 */
    user_data_t data;
    data.dumpfile = dumpfile;
    data.is_first_packet = 1;
    data.timeout_seconds = timeout_seconds;

    printf("\n패킷 캡처를 시작합니다...\n");
    printf("필터: %s\n", filter_exp);
    printf("출력 파일: %s\n", output_file);
    printf("캡처할 패킷 수: %d\n", num_packets);
    printf("캡처 타임아웃: %.0f초 (pcap_open_live 설정)\n", timeout_seconds);

    /*  헤더 출력 */
    printf("\n| %-5s | %-8s | %-39s | %-39s | %-7s | %-6s | %-30s |\n",
           "No", "Time(s)", "Source IP", "Destination IP", "Proto", "Length", "Info");
    printf("------------------------------------------------------------------------------------------------------------------------------------\n");

    /* 패킷 캡처 시작 */
    int ret;
    ret = pcap_loop(adhandle, num_packets, packet_handler, (u_char *)&data);

    if (ret == -1) {
        fprintf(stderr, "캡처 중 오류 발생: %s\n", pcap_geterr(adhandle));
    } else if (ret == -2) {
        printf("\n캡처 타임아웃에 도달하여 패킷 캡처를 중지합니다.\n");
    }

    /* 덤프 파일과 어댑터 닫기 */
    pcap_dump_close(dumpfile);
    pcap_close(adhandle);
    pcap_freealldevs(alldevs);

    /* 캡처 통계 정보 출력 */
    printf("\n캡처 완료.\n");
    printf("# Total number of packets : %d\n", stats.captured_packets);
    printf("IPv4 packets: %lu\n", stats.ip_packets);
    printf("IPv6 packets: %lu\n", stats.ipv6_packets);
    printf("Non-IP packets: %lu\n", stats.non_ip_packets);
    printf("TCP packets: %lu\n", stats.tcp_packets);
    printf("UDP packets: %lu\n", stats.udp_packets);

    /* 패킷 분석 시작 */
    if (stats.captured_packets > 0) {
        analyze_packets(output_file);
    } else {
        printf("캡처된 패킷이 없어 분석을 진행할 수 없습니다.\n");
    }

    return EXIT_SUCCESS;
}
