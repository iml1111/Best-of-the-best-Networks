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
	
	int i,j,nextck,sport,dport;
	char sip[20]={0};
	char dip[20]={0};
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
	
		ethh =(struct ether_header *)packet;
		packet +=14;
	       
		if( ntohs(ethh->ether_type) == ETHERTYPE_IP ){	
			iph =(struct ip *)packet;
        	        inet_ntop(AF_INET,&(iph->ip_src),sip,sizeof(sip));
	                inet_ntop(AF_INET,&(iph->ip_dst),dip,sizeof(dip));
			packet += (iph->ip_hl * 4);
		
			if(iph->ip_p == IPPROTO_TCP){
				tcph =(struct tcphdr *)packet;
				sport = ntohs(tcph->th_sport);
				dport = ntohs(tcph->th_dport);
				packet += (tcph->th_off * 4);
				
				if(sport == 80 || dport == 80){
             		       	        printf("=============================\n");
			         	printf("eth.smac = "); for(j=0;j<6;j++)printf("%02x:",ethh->ether_shost[j]); printf("\n");
	                        	printf("eth.dmac = "); for(j=0;j<6;j++)printf("%02x:",ethh->ether_dhost[j]); printf("\n");
                	        	printf("ip.sip = %s\n",sip);
	                		printf("ip.dip = %s\n",dip);
                                    	printf("tcp.sport = %d\n",sport);
                               	        printf("tcp.dport = %d\n",dport);

					printf("data:\n");
                        		for(j=1;j<=ntohs(iph->ip_len) - (tcph->th_off * 4) - (iph->ip_hl * 4) - 14;j++){
                        			printf("%02x ",*packet);
                        			packet++;

						if(j % 20 == 0)
        	               	                printf("\n");
	                       		 }
			       		 printf("\n=============================\n");
				}
			}
		}
	}
	pcap_close(handle);	
	return(0);
 }
