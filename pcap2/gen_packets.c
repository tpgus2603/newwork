/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies 
 * nor the names of its contributors may be used to endorse or promote 
 * products derived from this software without specific prior written 
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "myheader.h"

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

int main()
{
	pcap_if_t			*alldevs;
	pcap_if_t			*d;
	pcap_addr_t			*a;
	pcap_t				*adhandle;
	char				errbuf[PCAP_ERRBUF_SIZE+1];
	struct sockaddr		*saddr = NULL;
	u_char				packet[4096] = { 0 };
	int					pklen, i;
	int					dnum, snum, pnum;
	int arp_op;
	
#ifdef _WIN32
	WSADATA wsadata;
	int err = WSAStartup(MAKEWORD(2,2), &wsadata);

	if (err != 0) {
		fprintf(stderr, "WSAStartup failed: %d\n", err);
		exit(1);
	}
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		WSACleanup();
		exit(1);
	}
#endif
	
	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
#ifdef _WIN32
		WSACleanup();
#endif
		exit(1);
	}
	
	/* Scan the list printing every entry */
	ifprint0(alldevs, &dnum);

	printf("Enter the interface number (1-%d):", dnum);
	scanf("%d", &snum);

	if (snum < 1 || snum > dnum)
	{
		printf("\nInterface number out of range.\n");
		pcap_freealldevs(alldevs); /* Free the device list */
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < snum - 1; d = d->next, i++);

	/* IP addresses */
	for (a = d->addresses; a; a = a->next)
		if (a->addr != NULL && a->addr->sa_family == AF_INET) {
			struct sockaddr_in* ipv4 = (struct sockaddr_in*)a->addr;
#ifdef _WIN32
			char ip[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET, &ipv4->sin_addr, ip, INET_ADDRSTRLEN);
			printf("\n\tSelected interface: %s, IP address: %s\n\n", d->name, ip);
#else
			printf("\n\tSelected interface: %s, IP address: %s\n\n", d->name, inet_ntoa(ipv4->sin_addr));
#endif
	}

	/* Open the adapter */
	if ((adhandle = pcap_open_live(d->name,	// name of the device
		65536,		// portion of the packet to capture. 
		1,			// promiscuous mode (nonzero means promiscuous)
		1000,		// read timeout
		errbuf		// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
		// Free the device list
		pcap_freealldevs(alldevs);
		return -1;
	}

	// Select packet type
	printf("Select the packet type (1:udp, 2:tcp, 3:icmp, 4:arp): ");
	scanf("%d", &pnum);
	
	// Packet generation
	switch(pnum) {
		case 4:
			arp_op = ARPOP_REQUEST; // ARP request, ARPOP_REPLY for reply
			//sip = "192.168.0.210";
			sip = "192.168.0.10";
			dip = "192.168.0.12";
			//u_char	smac[6] = { 0x0a, 0x0b, 0x0c, 0x01, 0x02, 0x03 };	// sender mac address in ARP
			u_char	smac[6] = { 0x14, 0x18, 0xc3, 0x7e, 0xdc, 0x0e };
			u_char	tmac[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };	// target mac address in ARP
			if ( arp_op == ARPOP_REQUEST )
				for (i = 0; i < 6; i++) dst_mac[i] = 0xff;
			generate_packet_arp(packet, arp_op, smac, tmac, &pklen); 
			break;
		default:
			generate_packet_tcp_udp(packet, &pklen);
			break;
	};

	int heth = sizeof(struct eth_header);
	int hip = sizeof(struct ip_header);
	int hudp = sizeof(struct udp_header);
	int htcp = sizeof(struct tcp_header);
	printf("in main: ethype=0x%02x%02x pklen=%d\n", packet[12], packet[13], pklen);
	//printf("in main: ipporto=%d udata=%c %c\n", packet[heth+10], packet[heth+hip+hudp], packet[heth+hip+hudp+1]);


	// Send the packet
	int res = pcap_sendpacket(adhandle, packet, pklen);
	if (res == 0 )
		printf("Packet sent successfully .....\n");
	else
		printf("Packet sent error: res=%d err=%s.....\n",res, pcap_geterr(adhandle));

	/* Free the device list */
	pcap_freealldevs(alldevs);

#ifdef _WIN32
	WSACleanup();
#endif
	return 0;
}

void ifprint1(pcap_if_t* alldevs)
{
	pcap_if_t*		d;
	pcap_addr_t*	a;
	int				i = 0;

	for (d = alldevs; d; d = d->next)
	{
		/* Name */
		printf("[%d] %s\n", ++i, d->name);

		/* Description */
		if (d->description)
			printf("\tDescription: %s\n", d->description);

		/* Loopback Address*/
		printf("\tLoopback: %s\n", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");

		/* IP addresses */
		for (a = d->addresses; a; a = a->next) {
			printf("\tAddress Family: #%d\n", a->addr->sa_family);

			switch (a->addr->sa_family)
			{
			case AF_INET:
				printf("\tAddress Family Name: AF_INET\n");
				break;

			case AF_INET6:
				printf("\tAddress Family Name: AF_INET6\n");
				break;

			default:
				printf("\tAddress Family Name: Unknown\n");
				break;
			}
			if (a->addr && a->addr->sa_family > 0)
				//printf("\tAddress: %s\n", inet_ntoa((struct sockaddr_in)(a->addr->sin)));
				printf("\tAddress: %s\n", iptos(a->addr));
			if (a->netmask && a->netmask->sa_family > 0)
				printf("\tNetmask: %s\n", iptos(a->netmask));
			if (a->broadaddr && a->broadaddr->sa_family > 0)
				printf("\tBroadcast Address: %s\n", iptos(a->broadaddr));
			if (a->dstaddr && a->dstaddr->sa_family > 0)
				printf("\tDestination Address: %s\n", iptos(a->dstaddr));
		}
		printf("\n");
	}
}

void ifprint0(pcap_if_t* alldevs, int* dnum)
{
	pcap_if_t*		d;
	pcap_addr_t*	a;
	int				i = 0;

	printf("%-25s %-35s %-40s %s\n", "Index", "Name", "Description", "IPv4 address");
	for (d = alldevs; d; d = d->next)
	{
		/* Name */
		printf("[%2d] %-50s ", ++i, d->name);

		/* Description */
		if (d->description)
			printf("%-45s", d->description);

		/* IP addresses */
		for (a = d->addresses; a; a = a->next) {
			if (a->addr->sa_family == AF_INET)
				if (a->addr > 0)
					printf(" %s", iptos(a->addr));
		}
		printf("\n");
	}
	*dnum = i;
}

#define ADDR_STR_MAX 128
const char* iptos(struct sockaddr *sockaddr)
{
  static char address[ADDR_STR_MAX] = {0};
  int gni_error = 0;

  gni_error = getnameinfo(sockaddr,
      sizeof(struct sockaddr_storage),
      address,
      ADDR_STR_MAX,
      NULL,
      0,
      NI_NUMERICHOST);
  if (gni_error != 0)
  {
    fprintf(stderr, "getnameinfo: %s\n", gai_strerror(gni_error));
    return "ERROR!";
  }

  return address;
}

void	generate_packet_tcp_udp(u_char* packet, int *pklen)
{
	char          			sendbuf[4096] = { 0 };
	struct eth_header		*eth;
	struct ip_header		*iph;
	struct udp_header		*udph;
	char					*udata;
	size_t					dlen;
	struct pseudo_header	psh;

	/* Prepare headers*/
	eth		= (struct eth_header*)sendbuf;
	iph		= (struct ip_header*)(sendbuf + sizeof(struct eth_header));
	udph	= (struct udp_header*)(sendbuf + sizeof(struct eth_header) + sizeof(struct ip_header));
	udata	= (char*)(sendbuf + sizeof(struct eth_header) + sizeof(struct ip_header) + sizeof(struct udp_header));

	// Application data
	strcpy(udata, app_data);
	*pklen = (int)sizeof(struct eth_header) + (int)sizeof(struct ip_header) + (int)sizeof(struct udp_header) + (int)strlen(udata);

	printf("in create_send_packet(): str=%s strlen=%d pklne=%d \n", udata, (int)strlen(udata), *pklen);
	printf("in create_send_packet(): eth=%d iph=%d udph=%d udata=%d pklen=%d \n", (int)sizeof(struct eth_header),
		(int)sizeof(struct ip_header), (int)sizeof(struct udp_header), (int)strlen(udata), *pklen);

	// Ethernet header
	get_header_ethernet(eth);

	// IP header
	dlen = strlen(udata);
	get_header_ip(iph);

	// TCP/UDP header
	if ( protocol == IPPROTO_UDP )
		get_header_udp(udph);

	//void get_header_udp(struct udp_header* udph, struct ip_header* iph);
	memcpy(packet, sendbuf, sizeof(sendbuf));
}

// Ethernet header generation
void get_header_ethernet(struct eth_header *eth) {

	// copy destination mac to ethernet header
	memcpy(eth->dst_mac, dst_mac, 6);

	// copy source mac to ethernet header
	memcpy(eth->src_mac, src_mac, 6);

	// EtherType 설정 (네트워크 바이트 순서로 변환)
	eth->ethertype = htons(etype);
}

void get_header_ip(struct ip_header* iph)
{
	uint32_t 			src_ip, dst_ip;
	uint16_t			upp_len, checksum = 0;
	uint8_t 			buffer[4096] = { 0 };

	// IP header fields example
#ifndef _WIN32
	src_ip = inet_addr(sip);			// source IP address
	dst_ip = inet_addr(dip);			// destination IP address
#else
	inet_pton(AF_INET, sip, &src_ip);	// source IP address
	inet_pton(AF_INET, dip, &dst_ip);	// destination IP address
#endif

	if (protocol == IPPROTO_TCP)
		upp_len = 20 + sizeof(struct tcp_header) + strlen(app_data);
	else
		upp_len = 20 + sizeof(struct udp_header) + strlen(app_data);

	iph->version			= 4;				// IPv4
	iph->ihl				= 5;				// Header Length (5 words = 20 bytes), no option
	iph->tos				= 0;				// Default TOS
	iph->total_length		= htons(upp_len);	// no option
	iph->id					= htons(54321);		// Example Identification
	iph->fragment_offset	= 0;				// No fragmentation
	iph->ttl				= 64;				// Default TTL
	iph->protocol			= protocol;			// Protocol (TCP, UDP, ICMP, etc)
	iph->checksum			= checksum;			// Will be calculated later
	iph->src_ip				= src_ip;	// Convert to network byte order
	iph->dst_ip				= dst_ip;	// Convert to network byte order

	memcpy(buffer, iph, sizeof(struct ip_header));
	
	// checksum calculation
	iph->checksum			= calculate_checksum(buffer, sizeof(struct ip_header));

	//memcpy(buffer, iph, sizeof(struct ip_header));
	//checksum = calculate_checksum(buffer, sizeof(struct ip_header));
	//printf("in get_header_ip: checksum2 = %u (%u) iphlen=%d \n", checksum, iph->checksum, sizeof(struct ip_header));
}

// Checksum Calculation
uint16_t calculate_checksum(uint8_t* buffer, int length) {
	uint32_t	checksum	= 0;
	uint16_t*	buffer_16	= (uint16_t*)buffer;

	printf("in calc_checksum: length=%d\n", length);

	// Padding zero for odd number buffer
	if (length % 2 == 1) {
		buffer[length] = 0;
		length += 1;
	}

	while (length > 1) {
		checksum += *buffer_16++;  // 2bytes
		length -= 2;
	}
	// Wrap around for carry over 16-bits length
	checksum = (checksum >> 16) + (checksum & 0xFFFF);

	// one's complement
	checksum = ~checksum;

	return checksum;
}

void	get_header_udp(struct udp_header* udph)
{
	struct pseudo_header	psh;
	uint32_t				checksum = 0;
	uint8_t 				buffer[4096] = { 0 };
	int						hlen;

	udph->src_port	= htons(src_port);			// Convert to network byte order
	udph->dst_port	= htons(dst_port);			// Convert to network byte order
	udph->length	= htons(sizeof(struct udp_header) + strlen(app_data));
	udph->checksum	= 0;						// Optional for UDP, can be left as 0

	// Get pseudo header
	get_header_pseudo(&psh);
	//printf("in udp(): udplen=%d pshlen=%d\n", udph->length, psh.length);
	
	memcpy(buffer, &psh, sizeof(struct pseudo_header));
	memcpy(buffer + sizeof(struct pseudo_header), udph, sizeof(struct udp_header));
	memcpy(buffer + sizeof(struct pseudo_header) + sizeof(struct udp_header), app_data, strlen(app_data));
	hlen = (int)sizeof(struct pseudo_header) + (int)sizeof(struct udp_header) + (int)strlen(app_data);
	udph->checksum = calculate_checksum(buffer, hlen);

	// for validation
	memcpy(buffer + sizeof(struct pseudo_header), udph, sizeof(struct udp_header));
	int h1 = (int)sizeof(struct pseudo_header) + (int)sizeof(struct udp_header);
	printf("in gen_udp(): psheln=%d d[0]=%c d[1]= %c checksum1 = %d, checksum2 = %d\n", hlen, buffer[h1], buffer[h1+1], udph->checksum, calculate_checksum(buffer, hlen));
}

void	get_header_pseudo(struct pseudo_header *psh)
{
	uint32_t 			src_ip, dst_ip;

	// IP header fields example
#ifndef _WIN32
	src_ip = inet_addr(sip);			// source IP address
	dst_ip = inet_addr(dip);			// destination IP address
#else
	inet_pton(AF_INET, sip, &src_ip);	// source IP address
	inet_pton(AF_INET, dip, &dst_ip);	// destination IP address
#endif

	// pseudo header 
	psh->src_addr	= src_ip;
	psh->dst_addr	= dst_ip;
	psh->zeros		= 0;
	psh->protocol	= protocol;
	if (protocol == IPPROTO_TCP)
		psh->length = htons(sizeof(struct tcp_header) + strlen(app_data));
	else
		psh->length = htons(sizeof(struct udp_header) + strlen(app_data));
}

void	generate_packet_arp(u_char *packet, int op, u_char* smac, u_char* tmac, int *pklen)
{
	u_char          		sendbuf[4096] = { 0 };
	struct eth_header		*eth;
	struct arp_message		*arph;
	uint32_t 				src_ip=0, dst_ip=0;

	/* Prepare headers*/
	eth		= (struct eth_header*)sendbuf;
	arph	= (struct arp_message*)(sendbuf + sizeof(struct eth_header));

	// Ethernet header
	etype = ETHERTYPE_ARP;			// ethernet type for ARP
	get_header_ethernet(eth);

	// IP address manipulation
	inet_pton(AF_INET, sip, &src_ip);	// source IP address
	inet_pton(AF_INET, dip, &dst_ip);	// destination IP address

	// ARP Message
	arph->ar_hrd = htons(ARPHRD_ETHER);		// Format of hardware address
    arph->ar_pro = htons(ETHERTYPE_IP);		// Format of protocol address
    arph->ar_hln = 6;						// Length of hardware address
    arph->ar_pln = 4;						// Length of protocol address
    arph->ar_op  = htons(op);				// ARP opcode (1:request, 2:reply)
	
	memcpy(arph->ar_sha, smac, 6);			// Sender hardware address
	arph->ar_sip = src_ip;					// Sender IP address
	memcpy(arph->ar_tha, tmac, 6);			// Target hardware address
	arph->ar_tip = dst_ip;					// Target IP address	

	*pklen = sizeof(struct eth_header) + sizeof(struct arp_message);
	if (*pklen <= ORIG_PACKET_LEN)
		*pklen = ORIG_PACKET_LEN;

	memcpy(packet, sendbuf, sizeof(sendbuf));
}
