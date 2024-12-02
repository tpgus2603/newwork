//
// Packet Capture Example: Onlie packet capture
//
#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <pcap.h>
#include <pcap/pcap.h>
//#include <winsock.h>
#include <stdio.h>
#include <stdlib.h>

char* iptos(u_long in);

#define     SNAPLEN	    68       // captured packet size
#define     MAXPKT      100	    // max number of stored pkts
pcap_t*     adhandle;
int         tot_cap_num = 0;
void online_dump(u_char* dumpfile, const struct pcap_pkthdr* pkt_hdr, const u_char* pkt_data);

main()
{
    pcap_if_t*          alldevs;
    pcap_if_t*          d;
    char                errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr* pkt_hdr;    // captured packet header
    const u_char*       pkt_data;   // caputred packet data
    time_t              local_tv_sec;
    struct tm*          ltime;
    char                timestr[16];

    int		i, ret;			// for general use
    int		ndNum = 0;	// number of network devices
    int		devNum;		// device Id used for online packet capture
    pcap_dumper_t*          dumpfile;

    //printf("default device: %s\n", pcap_lookupdev(errbuf));

    /* Retrieve the device list */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* Print the list */
    printf("\n");
    pcap_addr_t* a;
    for (d = alldevs; d; d = d->next)
    {
        // device name
        printf(" [%d] %s", ++ndNum, d->name);

        // description
        if (d->description)
            printf(" (%s) ", d->description);

        // loopback address
        // printf("\tLoopback: %s\n", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");

        // IP addresses
        for (a = d->addresses; a; a = a->next) {
            if (a->addr->sa_family == AF_INET) {
                if (a->addr)
                    printf("[%s]", iptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr));
                //if (a->netmask)
                //    printf("\tNetmask: %s\n", iptos(((struct sockaddr_in*)a->netmask)->sin_addr.s_addr));
                //if (a->broadaddr)
                //    printf("\tBroadcast Address: %s\n", iptos(((struct sockaddr_in*)a->broadaddr)->sin_addr.s_addr));
                //if (a->dstaddr)
                //    printf("\tDestination Address: %s\n", iptos(((struct sockaddr_in*)a->dstaddr)->sin_addr.s_addr));
                break;
            }
        }
        printf(" flag=%d\n", (int)d->flags);
    }
    printf("\n");
    /* error ? */
    if (ndNum == 0)
    {
        printf("\nNo interfaces found! Make sure Npcap is installed.\n");
        return -1;
    }

    /* select device for online packet capture application */
    printf(" Enter the interface number (1-%d):", ndNum);
    scanf("%d", &devNum);

    /* select error ? */
    if (devNum < 1 || devNum > ndNum)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Jump to the selected adapter */
    for (d = alldevs, i = 0; i < devNum - 1; d = d->next, i++);

    /* Open the adapter */
    if ((adhandle = pcap_open_live( d->name, // name of the device
                                    65536,     // portion of the packet to capture. 
                                                // 65536 grants that the whole packet will be captured on all the MACs.
                                    1,         // promiscuous mode
                                    1000,      // read timeout
                                    errbuf)     // error buffer
        ) == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\n Selected device %s is available\n\n", d->description);
    pcap_freealldevs(alldevs);

    dumpfile = pcap_dump_open(adhandle, "capdump.cap");

    // start the capture 
    pcap_loop(adhandle,           // capture device handler
                -1, 	          // forever
                online_dump,      // callback function
                (u_char*)dumpfile);   // arguments


    /* Close the handle */
    pcap_close(adhandle);
    return 0;
}

/* From tcptraceroute, convert a numeric IP address to a string : source Npcap SDK */
#define IPTOSBUFFERS	12
char* iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
    static short which;
    u_char* p;

    p = (u_char*)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

// Callback function for online dump
void online_dump(u_char* dumpfile, const struct pcap_pkthdr* pkt_hdr, const u_char* pkt_data)
{
    printf("(%4d) clen=%3d, len=%4d \r", tot_cap_num++, pkt_hdr->caplen, pkt_hdr->len);

    // save the packet on the dump file
    pcap_dump(dumpfile, pkt_hdr, pkt_data);

    if (tot_cap_num > MAXPKT) {
        printf("\n\n %d-packets were captured ...\n", tot_cap_num);
        // close all devices and files
        pcap_close(adhandle);
        pcap_dump_close(dumpfile);
        exit(0);
    }

}
