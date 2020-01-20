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
	    destPort = ntohs(tcpHeader->dest);//set destination port
        printf("Got a packet! \n");
        printf("Source IP: %s \n",sourceIP); //print sourceIP
        printf("Destination IP : %s \n",destIP); //print destination IP
	    printf("Destination Port: %d \n",destPort); //print destination port
    }

}


int main()
{
struct in_addr address; //not being used
pcap_t *handle; //the variable that catches the packets
char errbuf[PCAP_ERRBUF_SIZE]; //error buffer in case there is error
struct bpf_program fp; //filter handler
char filter_exp[] = "proto TCP and dst portrange 10-100";
bpf_u_int32 net; // capture IPv4 traffic

handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf); //open a device for capturing ROOT IS REQUIRED
printf("%s ",errbuf); //print the error buffer


pcap_compile(handle, &fp, filter_exp, 0, net); //compile the filtering requirement
pcap_setfilter(handle, &fp); //merge filter into the pcket capture

pcap_loop(handle, -1, got_packet, NULL); //catch packets infinitly using got_packet
pcap_close(handle); //free handle - packet capturer
return 0;

}

