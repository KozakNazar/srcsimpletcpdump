/********************************************************************/
/* mytcpdump.c // use libpcap0.8-dev and ubunt11.10(kern 3.0)       */
/* All source in one file: mytcpdump.c                              */
/* To compile: gcc mytcpdump.c -o mytcpdump -lpcap                  */
/* To run(use device name): sudo ./mytcpdump eth0                   */
/* After a while for statistic info press: Ctrl + C                 */
/*                                                                  */
/* to install libpcap use command: sudo apt-get install libpcap-dev */
/*                                                                  */
/*                                              Nazar Kozak         */
/********************************************************************/

/* For include MAC statistic                                        */
#define RUN_MAC_STATISTIC 0                                         //
#define DEBUG                                                       //  

#include <pcap.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/ip.h> 


typedef struct Info_MAC_ {
    u_int8_t	MAC[ETH_ALEN + 2];	          
    u_int16_t	count_in;	  
    u_int16_t	count_out;	    
} Info_MAC;

typedef struct Info_ip_ {
    struct	in_addr ip;	          
    u_int16_t	count_in;	  
    u_int16_t	count_out;	  
    u_int16_t	count_in_tcp;	  
    u_int16_t	count_out_tcp;	  
    u_int16_t	count_in_udp;	  
    u_int16_t	count_out_udp;	  

} Info_ip;


#define MAX_LIST_SIZE 2048
Info_MAC   infoList_MAC[MAX_LIST_SIZE];
u_int32_t last_MAC_number = 0;
u_int32_t last_new_MAC_number = 0;
Info_ip   infoList_ip[MAX_LIST_SIZE];
u_int32_t last_ip_number = 0;
u_int32_t last_new_ip_number = 0;

u_int32_t isEthernet = 0;

u_int getIpOffset(pcap_t* interf) {
    int type = pcap_datalink(interf);

    switch (type) 
    {
	case DLT_EN10MB:
            isEthernet = 1;
            return 14;
	case DLT_RAW:
            return 0;
	case DLT_LOOP:
            return 4;
        case DLT_LINUX_SLL: 
            return 16;
	default:
	    perror("bad interface\n");
	    //error("bad interface\n");		    
            return 14;
    }

}

void scanList_MAC(const u_int8_t* MAC) 
{
    for(last_MAC_number = 0; !(last_MAC_number>last_new_MAC_number);)
    {	
        if(!strncmp(infoList_MAC[last_MAC_number].MAC, MAC, ETH_ALEN))
        {
            return;
        }
        ++last_ip_number;
    }
    if (last_new_MAC_number < MAX_LIST_SIZE - 1)
    {
        last_MAC_number =++ last_new_MAC_number;
    }
    strncpy(infoList_MAC[last_MAC_number].MAC, MAC, ETH_ALEN);
}

void updateInfolist_MAC(const u_int8_t* MAC, u_int8_t inout/*0:in, 1-255:out*/)
{
    scanList_MAC(MAC);

    (inout)?(infoList_MAC[last_MAC_number].count_out++):(infoList_MAC[last_MAC_number].count_in++);
}

void scanList_ip(struct	in_addr ip)
{
    for(last_ip_number = 0; !(last_ip_number>last_new_ip_number);)
    {
        if((*(u_int32_t*)&infoList_ip[last_ip_number].ip) == (*(u_int32_t*)&ip))
        {
            return;
        }
        ++last_ip_number;
    }
    if (last_new_ip_number < MAX_LIST_SIZE - 1)
    {
        last_ip_number =++ last_new_ip_number;
    }
    infoList_ip[last_ip_number].ip = ip;

}

void updateInfolist_ip(struct	in_addr ip, u_int8_t	ip_p, u_int8_t inout/*0:in, 1-255:out*/)
{
    scanList_ip(ip);

    (inout)?(infoList_ip[last_ip_number].count_out++):(infoList_ip[last_ip_number].count_in++);
    
    if (ip_p == IPPROTO_TCP)
    {	
        (inout)?(infoList_ip[last_ip_number].count_out_tcp++):(infoList_ip[last_ip_number].count_in_tcp++);
    }
    else if (ip_p == IPPROTO_UDP)
    {
        (inout)?(infoList_ip[last_ip_number].count_out_udp++):(infoList_ip[last_ip_number].count_in_udp++);
    }

}

u_int ipOffset = 14;

void packetHandler(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    const struct ether_header* eptr;
    const struct ip* ip;
    u_int length = pkthdr->len;
    u_int hlen,off,version;
    int i;
    int len;

    if (isEthernet && RUN_MAC_STATISTIC)
    {
        eptr = (struct ether_header *) packet;
#ifdef DEBUG
        fprintf(stdout,"ethernet header source: %s", (char* )ether_ntoa(eptr->ether_shost));
        fprintf(stdout," destination: %s ", (char* )ether_ntoa(eptr->ether_dhost));
#endif
        updateInfolist_MAC(eptr->ether_dhost, 0);
        updateInfolist_MAC(eptr->ether_shost, 1);
    }

    ip = (struct ip*)(packet + ipOffset);
    length -= ipOffset;

    if (length < sizeof(struct ip))
    {
        printf("truncated ip %d",length);
        return;
    }

    len = ntohs(ip->ip_len);

    if(ip->ip_v != 4)
    {
      fprintf(stdout,"Unknown version %d\n",version);
      return;
    }

    if(ip->ip_hl < 5)
    {
        fprintf(stdout,"bad-hlen %d \n",hlen);
    }

    if(length < len)
        printf("\ntruncated IP - %d bytes missing\n",len - length);

    off = ntohs(ip->ip_off);
    if((off & 0x1fff) == 0 )
    {
#ifdef DEBUG
        fprintf(stdout,"IP: ");
        fprintf(stdout,"%s ", (char* )inet_ntoa(ip->ip_src));
        fprintf(stdout,"%s %d %d %d %d", (char* )inet_ntoa(ip->ip_dst), hlen,version,len,off);
        switch (ip->ip_p) 
        {
	    case IPPROTO_TCP:
            fprintf(stdout," TCP\n");
            break;
	    case IPPROTO_UDP:
            fprintf(stdout," UDP\n");
            break;
	    case IPPROTO_ICMP:
            fprintf(stdout," ICMP\n");
            break;
	    default:
	    fprintf(stdout," others\n");
            break;
        }
#endif
        updateInfolist_ip(ip->ip_dst, ip->ip_p, 0);
        updateInfolist_ip(ip->ip_src, ip->ip_p, 1);
    }

}

static pcap_t* desrc = NULL;
static int cleanup(int signo);

int main(int argc,char **argv)
{
    int i=0, count=0;
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);

    if(argc < 2){ 
        fprintf(stdout,"Use device name for capture\n");
        return 0;
    }
	
    desrc = pcap_open_live(argv[1], BUFSIZ, 0, -1, errbuf);

    ipOffset = getIpOffset(desrc); 

    sigset(SIGPIPE, cleanup);
    sigset(SIGTERM, cleanup);
    sigset(SIGINT, cleanup);

    printf("Capture started for device: %s. Press Cntr-C to Stop\r\n", argv[1]);
    pcap_loop(desrc, -1, packetHandler, (u_char* )&count);
	 
    return 0;
	
}

void dumpCapturedInfo(void)
{
    u_int32_t i;
    printf("Capture stoped\n");

    if (isEthernet && RUN_MAC_STATISTIC)
    {
        printf("List captured MAC\n");
        printf("N: ----MAC--------------------------\n");
        for(i = 1; i <= last_new_MAC_number; i++)
        {
            printf("%d: %s\n", i, (char* )ether_ntoa(infoList_MAC[i].MAC));
            printf("   rx/tx: (%d/%d)\n", infoList_MAC[i].count_in, infoList_MAC[i].count_out);
        }

        printf("------------------------------------\n");
    }

    printf("List captured ip\n");

    printf("N: ----IP---------------------------\n");
    for(i = 1; i <= last_new_ip_number; i++)
    {
        printf("%d: %s\n", i, (char* )inet_ntoa(infoList_ip[i].ip));
        printf("   rx/tx: (%d/%d)\n", infoList_ip[i].count_in, infoList_ip[i].count_out);
        printf("           TCP: rx/tx: (%d/%d)\n", infoList_ip[i].count_in_tcp, infoList_ip[i].count_out_tcp);
        printf("           UDP: rx/tx: (%d/%d)\n", infoList_ip[i].count_in_udp, infoList_ip[i].count_out_udp);
    }

    printf("------------------------------------\n");

}

static int cleanup(int signo)
{
#ifdef USE_WIN32_MM_TIMER
	if (timer_id)
		timeKillEvent(timer_id);
	timer_id = 0;
#elif defined(HAVE_ALARM)
	alarm(0);
#endif

#ifdef HAVE_PCAP_BREAKLOOP
	pcap_breakloop(desrc);
#else
	if (desrc != NULL && pcap_file(desrc) == NULL) {
		putchar('\n');
		(void)fflush(stdout);
                dumpCapturedInfo();
	}
	exit(0);
#endif

}



