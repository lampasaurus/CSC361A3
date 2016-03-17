#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>

#include <pcap.h>

const char *timestamp_string(struct timeval ts);
void problem_pkt(struct timeval ts, const char *reason);
void too_short(struct timeval ts, const char *truncated_hdr);



#define MAXPACKETS 10000
struct ip *iph[MAXPACKETS];
int packetcounter;

int main(int argc, char *argv[]){
	int i;
	pcap_t *pcap;
	struct pcap_pkthdr header;
	char errbuf[PCAP_ERRBUF_SIZE];
   	u_char *packet;

	if (argc < 2) {
    		fprintf(stderr, "Usage: %s <pcap>\n", argv[0]);
    		return(-1);
  	}
	if (argc < 2) {
    		fprintf(stderr, "Usage: %s <pcap>\n", argv[0]);
    		return(-1);
  	}
	//Opens the dump file
	printf("%s\n", argv[1]);
	pcap = pcap_open_offline(argv[1], errbuf);
   	if (pcap == NULL) {
     		fprintf(stderr,"Couldn't open pcap file %s: %s\n", argv[1], errbuf);
     		return(-1);
   	}
	//Loops through the packets and process them into connections
	packetcounter = 0;
	while((packet = pcap_next(pcap, &header))!=NULL){
		process_packet(packetcounter, packet, header.ts, header.caplen);
		//printf("packetcounter = %d ", packetcounter);
		//printPackets(iph[packetcounter], tcph[packetcounter], timestamps[packetcounter]);
		//compareconnection(timestamps[packetcounter],iph[packetcounter],tcph[packetcounter]);	
		packetcounter ++;
	}
}

void process_packet(int n, u_char *packet, struct timeval ts, u_int capture_len){
	//printf("Adding packet %d   ", n);
	struct ip *iphdr;
	//Cuts out the unwanted ethernet headers
	if(capture_len < sizeof(struct ether_header)){
		too_short(ts, "Ethernet header");
		return;	
	}
	packet += sizeof(struct ether_header);
	capture_len -= sizeof(struct ether_header);
	
	//Cuts out the unwanted IP header
	if (capture_len < sizeof(struct ip)){
		too_short(ts, "IP header");
		return;
	}
	iphdr = (struct ip*) packet;
	iph[n] = iphdr;
	//printf("Added packet %d\n", n);
}
const char *timestamp_string(struct timeval ts)
	{
	static char timestamp_string_buf[256];

	sprintf(timestamp_string_buf, "%d.%06d",
		(int) ts.tv_sec, (int) ts.tv_usec);

	return timestamp_string_buf;
	}

void problem_pkt(struct timeval ts, const char *reason)
	{
	fprintf(stderr, "%s: %s\n", timestamp_string(ts), reason);
	}

void too_short(struct timeval ts, const char *truncated_hdr)
	{
	fprintf(stderr, "packet with timestamp %s is truncated and lacks a full %s\n",
		timestamp_string(ts), truncated_hdr);
	}
