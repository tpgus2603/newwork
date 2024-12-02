// myheader.h 
// includes useful headers

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/socket.h>
#else
#include <winsock2.h>
#endif

#ifdef _WIN32
#pragma pack(push, 1)
#endif

#define		MAC_ADDR_LEN	6
#define		ARPOP_REQUEST	1		// ARP request
#define     ARPOP_REPLY     2
#define		ARPHRD_ETHER	1 		// Ethernet 10/100Mbps
#define		ETHERTYPE_IP	0x0800	// IP protocol
#define		ETHERTYPE_ARP	0x0806	// ARP protocol
#define     ORIG_PACKET_LEN 64

// Ethernet Header Structure
struct eth_header {
    uint8_t  dst_mac[6];  // Destination MAC Address
    uint8_t  src_mac[6];  // Source MAC Address
    uint16_t ethertype;   // EtherType (e.g., IPv4: 0x0800)
};

// ARP packet
#ifdef _WIN32
#pragma pack(push, 1)
struct arp_message
{
    uint16_t	ar_hrd;		// Format of hardware address
    uint16_t	ar_pro;		// Format of protocol address
    uint8_t		ar_hln;		// Length of hardware address
    uint8_t		ar_pln;		// Length of protocol address
    uint16_t	ar_op;		// ARP opcode (command)
	uint8_t		ar_sha[6];	// Sender hardware address
	uint32_t	ar_sip;		// Sender IP address
	uint8_t		ar_tha[6];	// Target hardware address
	uint32_t	ar_tip;		// Target IP address	
};
#pragma pack(pop)
#else
struct arp_message
{
    uint16_t	ar_hrd;		// Format of hardware address
    uint16_t	ar_pro;		// Format of protocol address
    uint8_t		ar_hln;		// Length of hardware address
    uint8_t		ar_pln;		// Length of protocol address
    uint16_t	ar_op;		// ARP opcode (command)
	uint8_t		ar_sha[6];	// Sender hardware address
	uint32_t	ar_sip;		// Sender IP address
	uint8_t		ar_tha[6];	// Target hardware address
	uint32_t	ar_tip;		// Target IP address	
}__attribute__((packed));
#endif
  
// IP header sturcute (IPv4)
struct ip_header {
    uint8_t  ihl : 4;			// Header Length
    uint8_t  version : 4;		// IP Version
    uint8_t  tos;				// Type of Service
    uint16_t total_length;		// Total Length
    uint16_t id;				// Identification
    uint16_t fragment_offset;	// Fragment Offset
    uint8_t  ttl;				// Time to Live
    uint8_t  protocol;			// Protocol (TCP: 6, UDP: 17)
    uint16_t checksum;			// Header Checksum
    uint32_t src_ip;			// Source IP Address
    uint32_t dst_ip;			// Destination IP Address
};


// UDP header sturcute
struct udp_header {
    uint16_t src_port;		// Source Port
    uint16_t dst_port;		// Destination Port
    uint16_t length;		// UDP Length
    uint16_t checksum;		// UDP Checksum
};

// TCP header structure
struct tcp_header {
    uint16_t src_port;			// Source Port
    uint16_t dst_port;			// Destination Port
    uint32_t seq_num;			// Sequence Number
    uint32_t ack_num;			// Acknowledgment Number
    uint8_t  offset : 4;		// Data Offset (Header Length)
    uint8_t  reserved : 4;		// Reserved
    uint8_t  flags;				// Control Flags
    uint16_t window;			// Window Size
    uint16_t checksum;			// Checksum
    uint16_t urgent_pointer;	// Urgent Pointer
};

// Pseudo-header for checksum calculation
struct pseudo_header {
    uint32_t	src_addr;		// Source IP Address
    uint32_t	dst_addr;		// Destination IP Address
    uint8_t 	zeros;			// zero bits
    uint8_t		protocol;		// protocol field in IP header
    uint16_t	length;			// length of TCP/UDP header + App data
};

// Ethernet header fields example
uint8_t		dst_mac[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };		// Broadcast MAC
//uint8_t		src_mac[6] = { 0x0a, 0x0b, 0x0c, 0x01, 0x02, 0x03 };		// Source MAC
uint8_t		src_mac[6] = { 0x14, 0x18, 0xc3, 0x7e, 0xdc, 0x0e };		// Source MAC
uint16_t	etype = 0x0800;

// IP hdaerd fields example
char        *sip = "192.168.0.10";
char        *dip = "192.168.0.120";
uint8_t		protocol = IPPROTO_UDP;

// TCP/UDP header fields example
uint16_t    src_port    = 9999;
uint16_t    dst_port    = 80;
uint32_t    seq_num     = 100;
uint32_t    ack_num     = 100;
uint8_t     flags       = 0x18;	// CEUAPRSF: 0x18="00011000"=ACK+PSH flags

// Application data
char        *app_data = "Hello World, I am the Hero !!!";

// Function prototypes
void		ifprint1(pcap_if_t* alldevs);
void		ifprint0(pcap_if_t* alldevs, int* dnum);
const char* iptos(struct sockaddr* sockaddr);

void		generate_packet_tcp_udp(u_char* packet, int* pklen);
void	    generate_packet_arp(u_char* packet, int op, u_char *smac, u_char *tmac, int* pklen);

void		get_header_ethernet(struct eth_header* eth);
void		get_header_ip(struct ip_header* iph);
void		get_header_tcp(struct tcp_header* tcph);
void		get_header_udp(struct udp_header* udph);
void	    get_header_pseudo(struct pseudo_header* psh);

uint16_t	calculate_checksum(uint8_t* buffer, int length);