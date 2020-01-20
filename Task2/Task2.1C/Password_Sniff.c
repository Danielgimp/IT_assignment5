#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <ctype.h>


void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{


const struct ether_header* ethernetHeader; //contains source and destination MAC addresses and protocols used
const struct ip* ipHeader; //contains the ip header data
const struct tcphdr* tcpHeader; 
tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
char sourceIP[INET_ADDRSTRLEN]; //source ip string
char destIP[INET_ADDRSTRLEN]; //destination ip string
u_int sourcePort, destPort; //contains source port and destination port

ethernetHeader = (struct ether_header*)packet; //obtaion all the ethernet properties from packet
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) //if packet type is IP continue
    {
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header)); //obtaion ip properties from packet
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN); //get source ip
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN); //get destination ip
		destPort = ntohs(tcpHeader->dest); //set destination port
        printf("Got a packet! \n");
        printf("Source IP: %s \n",sourceIP); //print sourceIP
        printf("Destination IP : %s \n",destIP); //print destination IP
	    printf("Destination Port: %d \n",destPort); //print destination port
		printf("Payload:\n");                     
    	  for(int i=0;i<header->len;i++) { //print packets data from the header
             	if(isprint(packet[i]))     //checks if the packet data is printable
                	printf("%c ",packet[i]);  //Print it 
             	else
                printf(" . "); //if data is not printable print a dot         
             		if((i%16==0 && i!=0) || i==header->len-1) //when finished printing packet data dwar a new line
                printf("\n"); 
    		}
    }

}


int main()
{
//printf("Hello! \n");

struct in_addr address; //not being used
pcap_t *handle; //the variable that catches the packets
char errbuf[PCAP_ERRBUF_SIZE]; //error buffer in case there is error
struct bpf_program fp; //filter handler
char filter_exp[] = "proto TCP and dst port 23";
bpf_u_int32 net; // capture IPv4 traffic

handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf); //open a device for capturing ROOT IS REQUIRED
printf("%s ",errbuf); //print the error buffer


pcap_compile(handle, &fp, filter_exp, 0, net); //compile the filtering requirement
pcap_setfilter(handle, &fp); //merge filter into the pcket capture

pcap_loop(handle, -1, got_packet, NULL); //catch packets infinitly using got_packet
pcap_close(handle); //free handle - packet capturer
return 0;

}
// Note: don’t forget to add "-lpcap" to the compilation command.
// For example: gcc -o sniff sniff.c -lpcap
