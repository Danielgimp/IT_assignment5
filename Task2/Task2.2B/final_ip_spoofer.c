#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#define SRC_IP "192.168.1.56"
#define DEST_IP "8.8.8.8"

int main()
{
    int sock;
    char send_buf[98], recv_buf[98], src_name[256], src_ip[15], dst_ip[15];
    struct ip *ip = (struct ip *)send_buf;
    struct icmp *icmp = (struct icmp *)(ip + 1);
    struct hostent *src_hp, *dst_hp;
    struct sockaddr_in src, dst;
    struct timeval t;
    int on;
    int bytes_sent;
    int dst_addr_len;
    

    /* Initialize variables */
    on = 1;
    memset(send_buf, 0, sizeof(send_buf));
     

    /* Get source IP address */
    if(gethostname(src_name, sizeof(src_name)) < 0)
    {
        perror("gethostname() error");
        exit(EXIT_FAILURE);
    }
    else
    {
        if((src_hp = gethostbyname(SRC_IP)) == NULL)
        {
            fprintf(stderr, "%s: Can't resolve, unknown source.\n", src_name);
            exit(EXIT_FAILURE);
        }
        else
            ip->ip_src = (*(struct in_addr *)src_hp->h_addr);
    }

    /* Get destination IP address */
    if((dst_hp = gethostbyname(DEST_IP)) == NULL)
    {
        if((ip->ip_dst.s_addr = inet_addr(DEST_IP)) == -1)
        {
            fprintf(stderr, "%s: Can't resolve, unknown destination.\n", DEST_IP);
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        ip->ip_dst = (*(struct in_addr *)dst_hp->h_addr);
        dst.sin_addr = (*(struct in_addr *)dst_hp->h_addr);
    }

    sprintf(src_ip, "%s", inet_ntoa(ip->ip_src));
    sprintf(dst_ip, "%s", inet_ntoa(ip->ip_dst));
    printf("Sending ICMP Packet From Spoofed Source IP: '%s' to Destination IP: '%s'\n", src_ip, dst_ip);

    /* Create RAW socket */
    if((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
    {
        perror("socket() error");

        /* If something wrong, just exit */
        exit(EXIT_FAILURE);
    }

    /* Socket options, tell the kernel we provide the IP structure */
    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
    {
        perror("setsockopt() for IP_HDRINCL error");
        exit(EXIT_FAILURE);
    }

    /* IP structure, check the ip.h */
    ip->ip_v = 4;
    ip->ip_hl = 5;
    ip->ip_tos = 0;
    ip->ip_len = htons(sizeof(16));
    ip->ip_id = htons(321);
    ip->ip_off = htons(0);
    ip->ip_ttl = 255;
    ip->ip_p = IPPROTO_ICMP;
    ip->ip_sum = 0;

    /* ICMP structure, check ip_icmp.h */
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 8;
    icmp->icmp_id = 123;
    icmp->icmp_seq = 5796;

    /* Set up destination address family */
    dst.sin_family = AF_INET;
   
               /* Get destination address length */
        dst_addr_len = sizeof(dst);

        /* Send packet */
        if((bytes_sent = sendto(sock, send_buf, sizeof(send_buf), 0, (struct sockaddr *)&dst, dst_addr_len)) < 0)
        {
            perror("sendto() error");
            printf("Failed to send packet.\n");
            fflush(stdout);
        }
         else
        {
            printf("Sent %d byte packet... ", bytes_sent);
            fflush(stdout);
                      
        } 
 
    /* close socket */
    close(sock);

    return 0;
}


