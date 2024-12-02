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

#define LINE_LEN 16

struct pcap_pkthdr_packed {
    unsigned int ts_sec;
    unsigned int ts_usec;
    unsigned int caplen;
    unsigned int len;
} __attribute__((packed));

// literals related to distinguishing protocols
#define ETHERTYPE_IP        0x0800
#define ETH_II_HSIZE        14      // frame size of ethernet v2
#define ETH_802_HSIZE       22      // frame size of IEEE 802.3 ethernet
#define IP_PROTO_IP         0       // IP
#define IP_PROTO_TCP        6       // TCP
#define IP_PROTO_UDP        17      // UDP
#define RTPHDR_LEN          12      // Length of basic RTP header
#define CSRCID_LEN          4       // CSRC ID length
#define EXTHDR_LEN          4       // Extension header length

unsigned long net_ip_count = 0;
unsigned long net_etc_count = 0;
unsigned long trans_tcp_count = 0;
unsigned long trans_udp_count = 0;
unsigned long trans_etc_count = 0;

// Macros
// pntohs : to convert network-aligned 16bit word to host-aligned one
#define pntoh16(p)  ((unsigned short)                       \
                    ((unsigned short)*((unsigned char *)(p)+0)<<8|  \
                     (unsigned short)*((unsigned char *)(p)+1)<<0))

// pntohl : to convert network-aligned 32bit word to host-aligned one
#define pntoh32(p)  ((unsigned int)*((unsigned char *)(p)+0)<<24|  \
                    (unsigned int)*((unsigned char *)(p)+1)<<16|  \
                    (unsigned int)*((unsigned char *)(p)+2)<<8|   \
                    (unsigned int)*((unsigned char *)(p)+3)<<0)

void do_ip_traffic_analysis(unsigned char* buffer)
{
    unsigned char ip_ver, ip_hdr_len, ip_proto;
    int ip_offset = 14;

    ip_ver = buffer[ip_offset] >> 4;        // IP version
    ip_hdr_len = buffer[ip_offset] & 0x0f;  // IP header length
    ip_proto = buffer[ip_offset + 9];       // protocol above IP

    if (ip_proto == IP_PROTO_UDP)
        trans_udp_count++;
    else if (ip_proto == IP_PROTO_TCP)
        trans_tcp_count++;
    else
        trans_etc_count++;
}

void do_traffic_analysis(unsigned char* buffer)
{
    unsigned short type;

    // ethernet type check
    type = pntoh16(&buffer[12]);

    if (type == 0x0800)
    {
        net_ip_count++;
        do_ip_traffic_analysis(buffer);
    }
    else
        net_etc_count++;
}

int main(int argc, char** argv)
{
    struct pcap_file_header fhdr;
    //struct pcap_pkthdr chdr;
    struct pcap_pkthdr_packed chdr;
    unsigned char buffer[2000];
    FILE* fin;
    int i = 0;

    fin = fopen("ccc.pcap", "rb");
    if (fin == NULL) {
        fprintf(stderr, "Error: could not open file 'ccc.pcap'\n");
        return 1;
    }

    if (fread(&fhdr, sizeof(fhdr), 1, fin) != 1) {
        fprintf(stderr, "Error: could not read pcap file header\n");
        fclose(fin);
        return 1;
    }

    while (fread(&chdr, sizeof(chdr), 1, fin) == 1) {
        if (fread(buffer, sizeof(unsigned char), chdr.caplen, fin) != chdr.caplen) {
            fprintf(stderr, "Error: could not read packet data (%d)\n",chdr.caplen);
            break;
        }
        do_traffic_analysis(buffer);
        i++;
    }
    fclose(fin);

    printf("#total number of packets : %d\n", i);
    printf("IP packets: %d\n", (int)net_ip_count);
    printf("non-IP packets: %d\n", (int)net_etc_count);
    printf("TCP packets: %d\n", (int)trans_tcp_count);
    printf("UDP packets: %d\n", (int)trans_udp_count);
    return 0;
}


