#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	
	int i,j,nextck;
	char buf[20]={0};
	char buf2[20]={0};
	struct ip *iph;
	struct tcphdr *tcph;
	struct ether_header *ethh;
	
	if(argc == 1){
		printf("No Interface\n");
		return -1;
	}	

	/* Define the device */
	dev = argv[1];
	
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Grab a packet */
	while(1){
		nextck = pcap_next_ex(handle, &header,&packet);
		if(nextck == 0) continue;
		else if(nextck == -1 || nextck == -2) break;		
		
		printf("=============================\n");
		ethh =(struct ether_header *)packet;
		printf("eth.smac = "); for(j=0;j<6;j++)printf("%02x:",ethh->ether_shost[j]); printf("\n");
                printf("eth.dmac = "); for(j=0;j<6;j++)printf("%02x:",ethh->ether_dhost[j]); printf("\n");

		packet +=14;
	       
		if( ntohs(ethh->ether_type) == ETHERTYPE_IP ){	
			iph =(struct ip *)packet;
        	        inet_ntop(AF_INET,&(iph->ip_src),buf,sizeof(buf));
	                inet_ntop(AF_INET,&(iph->ip_dst),buf2,sizeof(buf2));
			printf("ip.sip = %s\n",buf);
			printf("ip.dip = %s\n",buf2);
			packet += (iph->ip_hl * 4);
		
			if(iph->ip_p == IPPROTO_TCP){
				tcph =(struct tcphdr *)packet;
				printf("tcp.sport = %d\n",ntohs(tcph->th_sport));
				printf("tcp.dport = %d\n",ntohs(tcph->th_dport));
				packet += (tcph->th_off * 4);

				printf("data:\n");
                        	for(j=1;j<=ntohs(iph->ip_len) - (tcph->th_off * 4) - (iph->ip_hl * 4) - 14;j++){
                        	printf("%02x ",*packet);
                        	packet++;

				if(j % 20 == 0)
        	                printf("\n");
	                        }
			}
		}
                printf("\n==============================\n");

	}
	pcap_close(handle);	
	return(0);
 }
