#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <pcap.h>
#include "airodump-ng_iml.h"

int main(int argc, char *argv[]){
	
		
	int nextck;
	pcap_t *handle;	
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *packet;

	struct ieee80211_radiotap_header *rh;
	struct ieee80211_header *ih;
	struct tkip_parameters *tp;
	struct fixed_paprmeters *fp;
	
	struct beacon btap[100];
	struct probe ptap[100];
	int bcnt = 0;
	int pcnt = 0;
	int i,j,ck;
	int bc=0, pb=0, dt=0;

	if(argc == 1){
		printf("No Interface\n");
		return -1;
	}
	/* Define the device */
	dev = argv[1];

	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}

	/* Grab a packet */
	while(1){
		nextck = pcap_next_ex(handle, &header, &packet);	//receive packet
		if(nextck == 0) continue;
		else if(nextck == -1 || nextck == -2) break;

		rh = (struct ieee80211_radiotap_header *)packet;	//header
		packet += rh->len;
		ih = (struct ieee80211_header *)packet;
		packet += 24;
		if(ih->type == DATA_FRAME){
			tp = (struct tkip_parameters *)packet;
			packet += 8;
		}
		else if(ih->type == PROBE_RESPONSE 
					|| ih->type == BEACON_FRAME)		
			packet += 12;
		else
			continue;

		switch(ih->type){					// PROBE RESPONSE only
			case PROBE_RESPONSE :			
			pb++;
			for(ck=0,i=0;i<pcnt;i++){
				if(!memcmp(ih->mac3,ptap[i].bssid,6) 
					&& !memcmp(ih->mac1,ptap[i].station,6)){ 
					ck = 1;
					ptap[i].pwr = rh->signal;
					ptap[i].frames++;
					break;
				}
			}
			if(!ck){
				memcpy(ptap[pcnt].bssid,ih->mac3,6);
				memcpy(ptap[pcnt].station,ih->mac1,6);
				ptap[pcnt].pwr = rh->signal;
				ptap[pcnt].frames = 1;
				pcnt++;
			}
			break;


			case BEACON_FRAME:
			bc++;
			for(ck=0,i=0;i<bcnt;i++){
				if(!memcmp(btap[i].essid,packet+2,btap[i].eslen)
					&& !memcmp(btap[i].bssid,ih->mac3,6)){
					ck = 1;
					btap[i].pwr = rh->signal;
					btap[i].beacons++;
					break;
				}
			}
			if(ck==0){
				btap[bcnt].eslen = packet[1];
				memcpy(btap[i].essid,packet+2,btap[bcnt].eslen);
				memcpy(btap[i].bssid,ih->mac3,6);
				btap[bcnt].pwr = rh->signal;
				btap[bcnt].beacons = 1;
				btap[bcnt].data = 0;
				packet += (btap[bcnt].eslen + 1) + 10 + 3;
				btap[bcnt].channel = *packet; 
				bcnt++;
			}
			break;


			case DATA_FRAME:
			dt++;
			for(i=0;i<bcnt;i++)
				if(!memcmp(ih->mac3,btap[i].bssid,6)){
					btap[i].data++;
					break;
				}		
			break;
		}
		clear();
		printf("				AIRODUMP-NG?\n\n");
		printf("BEACON: %d\n",bc);
		printf("DATA: %d\n\n",dt);
		printf("BSSID                 POWER     beacons      #data       channel      essid\n");
		printf("-------------------------------------------------------------------------------\n");
		for(i=0;i<bcnt;i++){
			for(j=0;j<6;j++) printf("%02x:",btap[i].bssid[j]);
			printf("      -%d  ",256-(btap[i].pwr));
			printf("%10d ",btap[i].beacons);
			printf("%10d   ",btap[i].data);
			printf("%10d       ",btap[i].channel);
			for(j=0;j<btap[i].eslen;j++) printf("%c",btap[i].essid[j]);
			printf("\n");
		}
		printf("\n\nPROBE: %d\n\n",pb);
		printf("BSSID                STATION                   POWER       FRAMES\n");
		printf("--------------------------------------------------------------------------------\n");
		for(i=0;i<pcnt;i++){
			for(j=0;j<6;j++) printf("%02x:",ptap[i].bssid[j]);
			printf("   ");
			for(j=0;j<6;j++) printf("%02x:",ptap[i].station[j]);
			printf("          -%d   ",256-(ptap[i].pwr));
			printf("%10d   ",ptap[i].frames);
			printf("\n");
		}
		printf("--------------------------------------------------------------------------------\n");
		
	}

	return 0;
}
