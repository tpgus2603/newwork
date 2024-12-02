//
//device list


//#define LINUX
#define WINDOWS

#include <pcap.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef WINDOWS
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/socket.h>
#endif


char* iptos(u_long in);

int main() {
    pcap_if_t*      alldevs;
    pcap_if_t*      device;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0;

    // Retrieve the network device list
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return 1;
    }

    // Displya device list
    printf("###  Available network interfaces:\n");
    for (device = alldevs; device != NULL; device = device->next) {
        //printf("[%d] %s", ++i, device->name);
        printf("[%d] ", ++i);
        if (device->description) {
            printf(" (%s)", device->description);
        }
        else {
            printf(" (No description available) ");
        }
        //printf("\n";
        // Loopback Address
        //printf("\tLoopback: %s\n", (device->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");

        /* IP addresses */
        pcap_addr_t* a;
        for (a = device->addresses; a; a = a->next) {
            if (a->addr->sa_family == AF_INET) {
                if (a->addr) {
                    printf(" %s", iptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr));
                    //printf("\tAddress: %s", iptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr));
                }
                //if (a->netmask)
                //    printf("\tNetmask: %s", iptos(((struct sockaddr_in*)a->netmask)->sin_addr.s_addr));
                //if (a->broadaddr)
                //    printf("\tBroadcast Address: %s", iptos(((struct sockaddr_in*)a->broadaddr)->sin_addr.s_addr));
                //if (a->dstaddr)
                //    printf("\tDestination Address: %s", iptos(((struct sockaddr_in*)a->dstaddr)->sin_addr.s_addr));
            }
        }
        printf("\n");
    }

    if (i == 0) {
        printf("No interfaces found.\n");
    }

    // Free device handles
    pcap_freealldevs(alldevs);

    return 0;
}

/* From tcptraceroute, convert a numeric IP address to a string */
#define IPTOSBUFFERS    12
char* iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
    static short which;
    u_char* p;

    p = (u_char*)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    _snprintf_s(output[which], sizeof(output[which]), sizeof(output[which]), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}