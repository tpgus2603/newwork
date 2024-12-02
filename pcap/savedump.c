#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>

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

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
int maxpknum=0, cappknum=0;
const char* iptos(struct sockaddr *sockaddr);
pcap_t *adhandle;
	  
int main(int argc, char **argv)
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_dumper_t *dumpfile;
	
#ifdef _WIN32
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}
#endif


    /* Check command line */
	if(argc != 2)
	{
        printf("usage: %s filename", argv[0]);
        return -1;
    }
    
	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		return -1;
	}
    
    /* Print the list */
    for(d=alldevs; d; d=d->next)
    {
        printf("[%d] %s", ++i, d->name);
        if (d->description)
            printf(" (%s)", d->description);
        else
            printf(" (No description available)");

	/* IP addresses */
	pcap_addr_t* a;
	for (a = d->addresses; a; a = a->next) {
		if (a->addr->sa_family == AF_INET)
			if (a->addr)
				printf(" %s", iptos(a->addr));
	}
	printf("\n");
    }

    if(i==0)
    {
        printf("\nNo interfaces found! Make sure Npcap is installed.\n");
        return -1;
    }
    
    printf("\nEnter the interface number (1-%d):",i);
    scanf("%d", &inum);
    
    printf("Enter maximum number of packets to be captured (0: exit):");
    scanf("%d", &maxpknum);
    
    if(inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
		
	/* Jump to the selected adapter */
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
    
    /* Open the adapter */
    if ((adhandle= pcap_open_live(d->name,	// name of the device
			65536,			// portion of the packet to capture. (whole pakcet for 65535)
			1,			// promiscuous mode (nonzero means promiscuous)
			1000,			// read timeout
			errbuf			// error buffer
			 )) == NULL)
    {
	fprintf(stderr,"\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
	/* Free the device list */
	pcap_freealldevs(alldevs);
	return -1;
    }

    /* Open the dump file */
    dumpfile = pcap_dump_open(adhandle, argv[1]);

    if(dumpfile==NULL)
    {
	fprintf(stderr,"\nError opening output file\n");
	return -1;
    }
    
    printf("\nlistening on %s... Press Ctrl+C to stop...\n", d->description);
	
    /* At this point, we no longer need the device list. Free it */
    pcap_freealldevs(alldevs);
    
    /* start the capture */
    pcap_loop(adhandle, 0, packet_handler, (unsigned char *)dumpfile);

    pcap_close(adhandle);
    return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	/* save the packet on the dump file */
	pcap_dump(dumpfile, header, pkt_data);
	
	cappknum++;
	
	if (cappknum > maxpknum) {
        printf("\n\n %d-packets were captured ...\n", cappknum);
       	// close all devices and files
       	pcap_close(adhandle);
       	pcap_dump_close((pcap_dumper_t *)dumpfile);
       	exit(0);
	}
}


/* From tcptraceroute, convert a numeric IP address to a string */
#define ADDR_STR_MAX 128
const char* iptos(struct sockaddr *sockaddr)
{
	static char address[ADDR_STR_MAX] = {0};
	int gni_error = 0;

	gni_error = getnameinfo(sockaddr, sizeof(struct sockaddr_storage), address, ADDR_STR_MAX,
		NULL, 0, NI_NUMERICHOST);
	if (gni_error != 0)
	{
		fprintf(stderr, "getnameinfo: %s\n", gai_strerror(gni_error));
		return "ERROR!";
 	}

	return address;
}
