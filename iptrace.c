#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include<netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <stdint.h>
#include <pcap.h>

const char *timestamp_string(struct timeval ts);
float gettime(struct timeval ts0, struct timeval ts);
void problem_pkt(struct timeval ts, const char *reason);
void too_short(struct timeval ts, const char *truncated_hdr);
int16_t swap_int16( int16_t val );
struct myIP{
	char dst[INET_ADDRSTRLEN];
	char src[INET_ADDRSTRLEN];
	int ttl;
	int protocol;
	u_short offset;
	u_short id;
	int fragments;
	float time;
	uint16_t sequence
};
struct myrequest{
	struct myIP request;
	struct myIP last;
	int r;
	struct myIP responses[100];
	int fragments;
	int lastoffset;
	int offset;
	int sd;
	
};

void main(int argc, char *argv[]){
	int packetcounter = 0;
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
	pcap_t *pcap = pcap_open_offline(argv[1], errbuf);
   	if (pcap == NULL) {
     		fprintf(stderr,"Couldn't open pcap file %s: %s\n", argv[1], errbuf);
     		return(-1);
   	}
	//Finds the # of packets
	packetcounter = 0;
	while((packet = pcap_next(pcap, &header))!=NULL){
		packetcounter ++;
	}
	pcap_close(pcap);
	pcap = pcap_open_offline(argv[1], errbuf);
	//printf("%d packets\n", packetcounter);

	//Start dealing with the ip header here
	struct myIP myips[packetcounter];		
	struct timeval timestamp0;
	struct timeval *timepointer;
	struct myIP *myippointer;
	struct myIP *myippointer2;
	
	
	int n = 0;
	int j = 0;
	int k = 0;
	//Makes sure all structures are initialized
	for(n = 0; n < packetcounter; n++){
		myippointer = &myips[n];
		initializeip(myippointer);
	}
	n = 0;
	j = 0;

	//Loops through the packets and extract the IP header information
	while((packet = pcap_next(pcap, &header))!=NULL){
		//printf("processing%d\n",n);		
		if(n == 0) timestamp0 = header.ts;
		myippointer = &myips[n];
		process_packet(myippointer, packet, timestamp0, header.ts, header.caplen);
		n++;
	}
	//Find how many ICMP requests have actually been made
	int requestcounter = 0;
	for(n = 0; n < packetcounter; n++){
		//ICMP request = packet with ttl 1 and ICMP protocol and no offset
		if((myips[n].ttl == 1) && (myips[n].protocol == 1) && (myips[n].offset == 0)){
			requestcounter++;
		}
	}
	printf("%d requests\n", requestcounter);
	//Start gropuing packets into ICMP requests
	struct myrequest myrequests[requestcounter];
	struct myrequest *myrp;
	for(n = 0; n < requestcounter; n++){
		myrp = &myrequests[n];
		initializerequest(myrp);
	}
	//Set the initial requests
	j = 0;
	for(n = 0; n < packetcounter; n++){
		//ICMP request = packet with ttl 1 and ICMP protocol and no offset
		if((myips[n].ttl == 1) && (myips[n].protocol == 1) && (myips[n].offset == 0)){
			//myippointer = &myips[n];
			myrequests[j].request = myips[n];
			j++;
		}
	}
	//Finds fragments of the requests
	for(n = 0; n < packetcounter; n++){
		for(j = 0; j < requestcounter; j++){
			if((myips[n].id == myrequests[j].request.id)&&(myips[n].offset > 0)){
				myrequests[j].fragments++;
				if(myips[n].offset > myrequests[j].lastoffset) myrequests[j].lastoffset = myips[n].offset;
			}
		}
	}
	//Sort the packets into requests based on timestamps since I can't figure out how to extract the sequence numbers
	for(n = 0; n < packetcounter; n++){
		for(k = 0; k < requestcounter-1; k++){
			if((myips[n].time > myrequests[k].request.time && myips[n].time < myrequests[k+1].request.time)&&
				(strstr(myips[n].dst, myrequests[k].request.src)!= NULL)){
				if(strstr(myrequests[k].request.dst, myips[n].src)) {
					myrequests[k].last = myips[n];
				}else{
					myrequests[k].responses[myrequests[k].r] = myips[n];
					myrequests[k].r++;
				}
				//printf("n = %d k = %d\n", n, k);
			}
		}
	}
	//Finds the packets for the last request
	/*for(n = 0; n < packetcounter; n++){
		if((myips[n].time > myrequests[requestcounter].request.time){
			if(strstr(myips[n].dst, myrequests[requestcounter].request.src);
				
				//printf("n = %d k = %d\n", n, k);
		}
	}*/
	for(n = 0; n < requestcounter; n++){
		//printf("no = %d\n",n+1);
		//printmyip(myips[n]);
		printrequest(myrequests[n]);
	}
	//Finds the RTT to each router
	char used[16*packetcounter];
	float rtt=0.0;
	float sd=0;
	float times[packetcounter];
	int count=0;
	int i = 0;
	for(n = 0; n < requestcounter; n++){ 		//for all requests							
		for(k=0; k<myrequests[n].r;k++){	//for all responses in the requests					
			if(strstr(used, ("%s to %s",myrequests[n].request.src, myrequests[n].responses[k].src))==NULL){
				times[count] = myrequests[n].responses[k].time - myrequests[n].request.time;
				count++;

				for(j = n; j < requestcounter; j++){
					for(i=0; i < myrequests[j].r; i++){
						if((strstr(myrequests[n].request.src, myrequests[j].request.src)!=NULL)&&
						(strstr(myrequests[n].responses[k].src, myrequests[j].responses[i].src)!=NULL)){
							times[count] = myrequests[j].responses[i].time - myrequests[j].request.time;
							count++;
						}
					}
				} 
				for(j = 0; j<count;j++) rtt+= times[j];
				rtt = rtt/count;
				for(j = 0; j<count;j++){
					times[j] -= rtt;
					times[j] = times[j] * times[j];
					sd += times[j];
				}
				sd = sd/(count-1);
				strcat(used, ("%s to %s||||",myrequests[n].request.src, myrequests[n].responses[k].src));
				printf("Average RTT for %s to %s is: %f.  S.D: %f\n", myrequests[n].request.src, myrequests[n].responses[k].src, rtt, sd);
				sd = 0.0;
				rtt = 0.0;
				//printf("count = %d\n",count);
				count=0;
			}
		}
	}
	//printf("%s \n",used);
	pcap_close(pcap);
	
	
}
//Just makes sure everything is initialized
void initializerequest(struct myrequest *r){
	r->r=0;
	r->fragments=0;
	r->lastoffset=0;
	r->offset = 0;
	r->sd = 0;
}
void initializeip(struct myIP *myip){
	strcpy(myip->dst, " ");
	strcpy(myip->src, " ");
	myip->ttl = -1;
	int i = 0;	
	myip->protocol = 0;
	myip->time = 0.0;
	myip->offset = 0;
	myip->fragments = -1;
	myip->id = 0;
	myip->sequence = 0;
}
//Take a full ethernet encapsulation and extracts and ip header, saving it for further use
void process_packet(struct myIP *myip, u_char *packet,struct timeval ts0, struct timeval ts,  u_int capture_len){
	//printf("Adding packet %d   ", n);
	struct ip *iphdr;
	unsigned short iphdrlen;
	//Cuts out the unwanted ethernet headers
	if(capture_len < sizeof(struct ether_header)){
		too_short(ts, "Ethernet header");
		return;	
	}
	packet += sizeof(struct ether_header);
	capture_len -= sizeof(struct ether_header);
	
	//Singles out the IP header
	if (capture_len < sizeof(struct ip)){
		too_short(ts, "IP header");
		return;
	}
	
	iphdr = (struct ip*) packet;
	//printf("have iphdr\n");
	//Extracts IP header information
	struct in_addr daddr = iphdr->ip_dst;
	struct in_addr saddr = iphdr->ip_src;
	char dstAdd[INET_ADDRSTRLEN];
	char srcAdd[INET_ADDRSTRLEN];
	inet_ntop( AF_INET, &daddr, dstAdd, INET_ADDRSTRLEN );
	inet_ntop( AF_INET, &saddr, srcAdd, INET_ADDRSTRLEN );
	strcpy(myip->dst, dstAdd);
	strcpy(myip->src, srcAdd);
	myip->protocol = (int)iphdr->ip_p;
	myip->offset = ntohs(iphdr->ip_off)*8;
	myip->ttl = (int)iphdr->ip_ttl;
	myip->time = gettime(ts0, ts);
	myip->fragments = 0;
	myip->id = ntohs(iphdr->ip_id);

	//If it has ICMP protocol, extract the ICMP sequence
	;
	if(myip->protocol == 1){
		packet += iphdr->ip_hl*4;
		struct icmphdr *icmph = (struct icmphdr *)(packet);
		myip->sequence = swap_int16( (int16_t) ntohs(icmph->un.echo.sequence));
	}
}
void printrequest(struct myrequest r){
	printf("The IP address of the source node: %s\n", r.request.src);
	printf("The IP address of the ultimate destination node: %s\n", r.request.dst);
	printf("The IP addresses of the intermediary destination nodes:\n");
	int i = 0;		
	int protocols[256];
	for(i = 0; i <256; i++) protocols[i] = 0;
	protocols[r.request.protocol] = 1;
	for(i = 0; i < r.r; i++){
		protocols[r.responses[i].protocol] = 1; 
		printf("     Router %d: %s\n", i+1, r.responses[i].src);
	}
	printf("The values in the protocol field of the IP headers:\n");
	for(i = 0; i < 256; i++){
		if(protocols[i] == 1){
			printf("     %d",i);
			if(i == 1) printf(": ICMP");
			if(i == 6) printf(": TCP");
			if(i == 17) printf(": UDP");
			printf("\n");
		}
	}
	printf("The number of fragments created from the original datagram is: %d\n", r.fragments);
	printf("The offset of the last fragment is: %d\n\n", r.lastoffset);	
	//printf("request sequence %d\n", r.request.sequence);
	//printf("r = %d\n", r.r);
	//printf("request id %d\n\n", r.request.id);
} 
void printmyip(struct myIP myip){
	printf("id: %d\n", myip.id);
	//printf("src: %s\n", myip.src);
	//printf("dst: %s\n", myip.dst);
	//printf("ttl: %d\n", myip.ttl);
	//printf("offset: %d bits\n", myip.offset);
	printf("time: %f\n", myip.time);
	printf("protocol: %d\n", myip.protocol); 
	printf("sequence: %d\n", myip.sequence);
	printf("\n");
}

float gettime(struct timeval ts0, struct timeval ts){
	char tsbuf[256];
	char ts0buf[256];
	sprintf(tsbuf, "%d.%06d", (int) ts.tv_sec, (int) ts.tv_usec);
	sprintf(ts0buf, "%d.%06d", (int) ts0.tv_sec, (int) ts0.tv_usec);
	float t = strtod(tsbuf,NULL) - strtod(ts0buf, NULL);
	//printf("t0 - t = %f\n", t);
	return t;
}

int16_t swap_int16( int16_t val ) 
{
    return (val << 8) | ((val >> 8) & 0xFF);
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
