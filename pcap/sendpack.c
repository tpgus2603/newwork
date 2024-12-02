#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>

#ifdef _WIN32
#include <tchar.h>
BOOL LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}
#endif

/* case-insensitive string comparison that may mix up special characters and numbers */
int close_enough(char *one, char *two)
{
	while (*one && *two)
	{
		if ( *one != *two && !(
			(*one >= 'a' && *one - *two == 0x20) ||
			(*two >= 'a' && *two - *one == 0x20)
			))
		{
			return 0;
		}
		one++;
		two++;
	}
	if (*one || *two)
	{
		return 0;
	}
	return 1;
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


#define ORIG_PACKET_LEN 64
int main(int argc, char **argv)
{
	pcap_t *fp;
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE] = {0};
	u_char packet[ORIG_PACKET_LEN] = 
		/* Ethernet frame header */
		"\xff\xff\xff\xff\xff\xff" /* dst mac */
		"\x02\x02\x02\x02\x02\x02" /* src mac */
		"\x08\x00" /* ethertype IPv4 */
		/* IPv4 packet header */
		"\x45\x00\x00\x00" /* IPv4, minimal header, length TBD */
		"\x12\x34\x00\x00" /* IPID 0x1234, no fragmentation */
		"\x10\x11\x00\x00" /* TTL 0x10, UDP, checksum (not required) */
		"\x00\x00\x00\x00" /* src IP (TBD) */
		"\xff\xff\xff\xff" /* dst IP (broadcast) */
		/* UDP header */
		"\x00\x07\x00\x07" /* src port 7, dst port 7 (echo) */
		"\x00\x00\x00\x00" /* length TBD, cksum 0 (unset) */
	;
	u_char *sendme = packet;
	size_t packet_len = ORIG_PACKET_LEN;
	pcap_if_t *ifaces = NULL;
	pcap_if_t *dev = NULL;
	pcap_addr_t *addr = NULL;

#ifdef _WIN32
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}
#endif

	
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs 오류: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
	list_devices();

	int i=0;
	int dev_num;
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs 오류: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    for (dev = alldevs; dev != NULL; dev = dev->next) {
        i++;
    }
	printf("\n패킷을 캡처할 인터페이스 번호를 입력하세요 (1-%d): ", i);
    char input_buffer[100];
    if (fgets(input_buffer, sizeof(input_buffer), stdin) != NULL) {
        size_t len = strlen(input_buffer);
        if (len > 0 && input_buffer[len - 1] == '\n') {
            input_buffer[len - 1] = '\0';
        }
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
		char *dev_selected = NULL;
	for (dev = alldevs, i = 1; i < dev_num && dev != NULL; dev = dev->next, i++);
    dev_selected = dev->name;
    printf("\n선택된 장치: %s\n", dev_selected);
  
	if (0 != pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf)) {
		fprintf(stderr, "Failed to initialize pcap lib: %s\n", errbuf);
		return 2;
	}

	/* Find the IPv4 address of the device */
	if (0 != pcap_findalldevs(&ifaces, errbuf)) {
		fprintf(stderr, "Failed to get list of devices: %s\n", errbuf);
		return 2;
	}

	for (dev = ifaces; dev != NULL; dev = dev->next)
	{
		if (close_enough(dev->name, dev_selected))
		{
			break;
		}
	}
	if (dev == NULL) {
		fprintf(stderr, "Could not find %s in the list of devices\n", dev_selected);
		return 3;
	}

	for (addr = dev->addresses; addr != NULL; addr = addr->next)
	{
		if (addr->addr->sa_family == AF_INET)
		{
			break;
		}
	}
	if (addr == NULL) {
		fprintf(stderr, "Could not find IPv4 address for %s\n", dev_selected);
		return 3;
	}

	/* Fill in the length and source addr and calculate checksum */
	packet[14 + 2] = 0xff & ((ORIG_PACKET_LEN - 14) >> 8);
	packet[14 + 3] = 0xff & (ORIG_PACKET_LEN - 14);
	/* UDP length */
	packet[14 + 20 + 4] = 0xff & ((ORIG_PACKET_LEN - 14 - 20) >> 8);
	packet[14 + 20 + 5] = 0xff & (ORIG_PACKET_LEN - 14 - 20);
#ifdef _WIN32
	*(u_long *)(packet + 14 + 12) = ((struct sockaddr_in *)(addr->addr))->sin_addr.S_un.S_addr;
#else
	*(u_long *)(packet + 14 + 12) = ((struct sockaddr_in *)(addr->addr))->sin_addr.s_addr;;	
#endif
	uint32_t cksum = 0;
	for (int i=14; i < 14 + 4 * (packet[14] & 0xf); i += 2)
	{
		cksum += *(uint16_t *)(packet + i);
	}
	while (cksum>>16)
		cksum = (cksum & 0xffff) + (cksum >> 16);
	cksum = ~cksum;
	*(uint16_t *)(packet + 14 + 10) = cksum;

	/* Open the adapter */
	if ((fp = pcap_open_live(dev_selected,		// name of the device
							 0, // portion of the packet to capture. 0 == no capture.
							 0, // non-promiscuous mode
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by Npcap\n", dev_selected);
		return 2;
	}
	
	switch(pcap_datalink(fp))
	{
		case DLT_NULL:
			/* Skip Ethernet header, retreat NULL header length */
#define NULL_VS_ETH_DIFF (14 - 4)
			sendme = packet + NULL_VS_ETH_DIFF;
			packet_len -= NULL_VS_ETH_DIFF;
			// Pretend IPv4
			sendme[0] = 2;
			sendme[1] = 0;
			sendme[2] = 0;
			sendme[3] = 0;
			break;
		case DLT_EN10MB:
			/* Already set up */
			sendme = packet;
			break;
		default:
			fprintf(stderr, "\nError, unknown data-link type %u\n", pcap_datalink(fp));
			return 4;
	}
	
	/* Send down the packet */
	if (pcap_sendpacket(fp,	// Adapter
		sendme, // buffer with the packet
		packet_len // size
		) != 0)
	{
		fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
		return 3;
	}

	pcap_close(fp);	
	return 0;
}
