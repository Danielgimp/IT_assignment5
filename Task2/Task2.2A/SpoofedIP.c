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

int main(int argc, char *argv[])
{
    int sock;
    char send_buf[400], recv_buf[400], src_name[256], src_ip[15], dst_ip[15];
    struct ip *ip = (struct ip *)send_buf;
    struct hostent *src_hp, *dst_hp;
    struct sockaddr_in src, dst;
    int on;
    int bytes_sent;
    int dst_addr_len;
    

    /* Initialize variables */
    on = 1;
    memset(send_buf, 0, sizeof(send_buf));

    /* Check for valid args */
    if(argc < 2)
    {
        printf("\nUsage: %s <dst_server>\n", argv[0]);
        printf("- dst_server is the target\n");
        exit(EXIT_FAILURE);
    }

    /* Check for root access */
    if (getuid() != 0)
    {
        fprintf(stderr, "%s: This program requires root privileges!\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Get source IP address */
    if(gethostname(src_name, sizeof(src_name)) < 0)
    {
        perror("gethostname() error");
        exit(EXIT_FAILURE);
    }
    else
    {
        if((src_hp = gethostbyname("192.168.1.56")) == NULL)
        {
            fprintf(stderr, "%s: Can't resolve, unknown source.\n", src_name);
            exit(EXIT_FAILURE);
        }
        else
            ip->ip_src = (*(struct in_addr *)src_hp->h_addr);
    }

    /* Get destination IP address */
    if((dst_hp = gethostbyname(argv[1])) == NULL)
    {
        if((ip->ip_dst.s_addr = inet_addr(argv[1])) == -1)
        {
            fprintf(stderr, "%s: Can't resolve, unknown destination.\n", argv[1]);
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
    printf("Source IP: '%s' -- Destination IP: '%s'\n", src_ip, dst_ip);

    /* Create RAW socket */
    if((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
    {
        perror("socket() error");

        /* If something wrong, just exit */
        exit(EXIT_FAILURE);
    }

    /* Socket options, tell the kernel we provide the IP structure */
    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) //IP_HDRINCL - must contain IP Header
    {
        perror("setsockopt() for IP_HDRINCL error");
        exit(EXIT_FAILURE);
    }

    /* IP structure, check the ip.h */
    ip->ip_v = 4;
    ip->ip_hl = 5;
    ip->ip_tos = 0;
    ip->ip_len = htons(sizeof(send_buf));
    ip->ip_id = htons(321);
    ip->ip_off = htons(0);
    ip->ip_ttl = 255;
    ip->ip_p = IPPROTO_IP;
    ip->ip_sum = 0;

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
            printf("Sent %d byte packet sucessfully... \n", bytes_sent);

            fflush(stdout);
                  

           
        }
    

    
    /* close socket */
    close(sock);

    return 0;
}

