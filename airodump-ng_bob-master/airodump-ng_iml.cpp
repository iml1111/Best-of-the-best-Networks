#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <pcap.h>
#include "airodump-ng_iml.h"
#include <iostream>
#include <map>
using namespace std;
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
	
	//struct beacon btap[100];
	//struct probe ptap[100];
	struct beacon new_b;
	struct probe new_p;
	map<size_t, struct beacon> btap;
	map<size_t, struct beacon>:: iterator biter;
	map<size_t, struct probe> ptap;
	map<size_t, struct probe>:: iterator piter;
	uint8_t bsst[12];

	int bcnt = 0;
	int pcnt = 0;
	int i,j,ck;
	int bc=0, pb=0, dt=0;
	size_t hsh;

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
			memcpy(bsst,ih->mac3,6);
			memcpy(bsst+6,ih->mac1,6);
			hsh = hashl(bsst);
			piter = ptap.find(hsh);

			if(piter != ptap.end()){
				new_p = piter->second;
				new_p.pwr = rh->signal;
				new_p.frames++;

			}
			else{	
				memcpy(new_p.bssid,ih->mac3,6);
				memcpy(new_p.station,ih->mac1,6);
				new_p.pwr = rh->signal;
				new_p.frames = 1;
			}
			ptap[hsh] = new_p;

			break;


			case BEACON_FRAME:
			bc++;
			hsh = hashl(ih->mac3);
			biter = btap.find(hsh);

			if(biter != btap.end()){
				new_b = biter->second;
				new_b.pwr = rh->signal;
				new_b.beacons++;
			}
			else{
				new_b.eslen = packet[1];
				memcpy(new_b.essid,packet+2,new_b.eslen);
				memcpy(new_b.bssid,ih->mac3,6);
				new_b.pwr = rh->signal;
				new_b.beacons = 1;
				new_b.data = 0;
				packet += (new_b.eslen + 1) + 10 + 3;
				new_b.channel = *packet; 
			}
			btap[hsh] = new_b;
			break;


			case DATA_FRAME:
			dt++;
			hsh = hashl(ih->mac3);
			biter = btap.find(hsh);

			if(biter != btap.end()){
				new_b = biter->second;
				new_b.data++;
				btap[hsh] = new_b;
			}		
			break;
		}
		clearrr();
		printf("				AIRODUMP-NG?\n\n");
		printf("BEACON: %d\n",bc);
		printf("DATA: %d\n\n",dt);
		printf("BSSID                 POWER     beacons      #data       channel      essid\n");
		printf("-------------------------------------------------------------------------------\n");
		for(biter=btap.begin();biter != btap.end();biter++){
			for(j=0;j<6;j++) printf("%02x:",biter->second.bssid[j]);
			printf("      -%d  ",256-(biter->second.pwr));
			printf("%10d ",biter->second.beacons);
			printf("%10d   ",biter->second.data);
			printf("%10d       ",biter->second.channel);
			for(j=0;j<biter->second.eslen;j++) printf("%c",biter->second.essid[j]);
			printf("\n");
		}
		printf("\n\nPROBE: %d\n\n",pb);
		printf("BSSID                STATION                   POWER       FRAMES\n");
		printf("--------------------------------------------------------------------------------\n");
		for(piter=ptap.begin(); piter != ptap.end(); piter++){
			for(j=0;j<6;j++) printf("%02x:",piter->second.bssid[j]);
			printf("   ");
			for(j=0;j<6;j++) printf("%02x:",piter->second.station[j]);
			printf("          -%d   ",256-(piter->second.pwr));
			printf("%10d   ",piter->second.frames);
			printf("\n");
		}
		printf("--------------------------------------------------------------------------------\n");
		
	}

	return 0;
}
