#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <pcap.h>
#include <stdio.h>
#include <time.h>
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
const char* iptos(struct sockaddr *sockaddr);

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

#ifdef _WIN32
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}
#endif

	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
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
	
	printf("Enter the interface number (1-%d):",i);
	scanf("%d", &inum);
	
	if(inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	/* Jump to the selected adapter */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	
	/* Open the device */
	/* Open the adapter */
	if ((adhandle= pcap_open_live(d->name,	// name of the device
				 65536,		// portion of the packet to capture. 
						// 65536 grants that the whole packet will be captured on all the MACs.
				 1,		// promiscuous mode (nonzero means promiscuous)
				 1000,		// read timeout
				 errbuf		// error buffer
				)) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	printf("\nlistening on %s...\n", d->description);
	
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	
	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);
	
	pcap_close(adhandle);
	return 0;
}


/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;

	/*
	 * unused parameters
	 */
	(void)(param);
	(void)(pkt_data);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime=localtime(&local_tv_sec);
	strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
	
	printf("%s,%.6d len:%d\n", timestr, (int)header->ts.tv_usec, header->len);
	
}

/* From tcptraceroute, convert a numeric IP address to a string */
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

