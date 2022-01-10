#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

#define PROBE_RESPONSE 0x50
#define BEACON_FRAME 0x80
#define DATA_FRAME 0x08 

#define clearrr() printf("\033[H\033[J")

size_t hashl(uint8_t *input){
	const int ret_size = 32;
	size_t ret = 0x555555;
	const int per_char = 7;

	while(*input){
		ret ^= *input++;
		ret = ((ret << per_char) | ret >> (ret_size - per_char));
	}
	return ret;
}

struct beacon {				

	char essid[256];
	uint8_t eslen;
	uint8_t bssid[6];
	uint8_t pwr;
	int beacons;
	int data;
	uint8_t channel;
	// Encryption?

} __attribute__((__packed__));

struct probe {	
	
	uint8_t bssid[6];
	uint8_t station[6];
	uint8_t pwr;
	int frames;
	// Probe??
	
} __attribute__((__packed__));



struct ieee80211_radiotap_header {                      /*(24bytes)*/

        uint8_t        version;     
        uint8_t        pad;
        uint16_t       len;       		  /* entire length */
        uint32_t       present1;     
        uint32_t       present2;    
        uint8_t        flags;
        uint8_t        data_rate;
        uint16_t       ch;		/*channel freq*/
        uint16_t 	ch_flags;
        uint8_t 	signal;
        uint8_t    reserved;
        uint16_t 	rx_flags;
        uint8_t 	signal2;
        uint8_t 	antenna;

} __attribute__((__packed__));

struct ieee80211_header {	                      /*(24bytes)*/

	uint8_t 	type;
        uint8_t       control;
	uint16_t 	duration;
	uint8_t 	mac1[6];		
	uint8_t		mac2[6];		
	uint8_t		mac3[6];
	uint16_t 	fs_number;	

} __attribute__((__packed__));

struct tkip_parameters {		/*data frame only*/

	u_int8_t	 tkip[8];

} __attribute__((__packed__));

struct fixed_paprmeters {		/*probe response, beacon frame only  (12bytes)*/

	u_int8_t 	timestamp[8];
	u_int16_t	b_interval;
	u_int16_t	c_info;

} __attribute__((__packed__));
