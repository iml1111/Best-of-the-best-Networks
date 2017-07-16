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
int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	
	int i,j;
	struct ip *iph;
	struct tcphdr *tcph;
	struct ether_header *ethh;

	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	/* Grab a packet */
	while(1){
		packet = pcap_next(handle, &header);
		
		ethh =(struct ether_header *)packet;
		packet +=sizeof(struct ether_header);
		
		iph =(struct ip *)packet;
		packet += sizeof(struct ip);

		tcph =(struct tcphdr *)packet;
		packet += sizeof(struct tcphdr);
		printf("=============================\n");
		printf("eth.smac = "); for(j=0;j<6;j++)printf("%02x:",ethh->ether_shost[j]); printf("\n");
		printf("eth.dmac = "); for(j=0;j<6;j++)printf("%02x:",ethh->ether_dhost[j]); printf("\n");
		
		printf("ip.sip = %s\n",inet_ntoa(iph->ip_src));
		printf("ip.dip = %s\n",inet_ntoa(iph->ip_dst));

		printf("tcp.sport = %d\n",ntohs(tcph->th_sport));
		printf("tcp.dport = %d\n",ntohs(tcph->th_dport));
		
		printf("data:\n");
		for(j=0;j<(header.len)-sizeof(struct ether_header)-
					sizeof(struct ip)-sizeof(struct tcphdr);j++){
			printf("%02x ",*packet);
			packet++;

			if(j % 20 == 0 && j!=0)
			printf("\n");
		}
		printf("\n=============================\n");
	}
	pcap_close(handle);	
	return(0);
 }
