#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>


/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  printf("===========Packet Information===========\n");
  
  /* Ethernet Header */
  struct ethheader *eth = (struct ethheader *)packet;
  printf("1. Ethernet Header:\n");
  printf("Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_shost[0],
         eth->ether_shost[1],eth->ether_shost[2],eth->ether_shost[3],eth->ether_shost[4],
         eth->ether_shost[5]);
  printf("Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_dhost[0],
         eth->ether_dhost[1],eth->ether_dhost[2],eth->ether_dhost[3],eth->ether_dhost[4],
         eth->ether_dhost[5]);
  printf("\n");

  /* IP Header */
  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 
    printf("2. IP Header:\n");
    printf("Src IP: %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("Dst IP: %s\n", inet_ntoa(ip->iph_destip));
    printf("\n");
    
    /* TCP Header */
    if (ip->iph_protocol == IPPROTO_TCP) {
	    
      struct tcpheader * tcp = (struct tcpheader *)
                               (packet + sizeof(struct ethheader) + ip->iph_ihl * 4);
      printf("3. TCP Header:\n");
      printf("Src PORT:%d\n", ntohs(tcp->tcp_sport));
      printf("Dst PORT:%d\n", ntohs(tcp->tcp_dport));
      printf("\n");
      
      int msg_off = TH_OFF(tcp) * 4;
      int msg_len = ntohs(ip->iph_len) - (ip->iph_ihl * 4) - msg_off;
      if (msg_len > 32)
        msg_len = 32;
        
      printf("4. Message:\n");
      for (int i = 0; i< msg_len; i++) {
        printf("%02x", packet[sizeof(struct ethheader) + (ip->iph_ihl * 4) + msg_off + i]);
        if (i == 7 | i == 23)
          printf(" | ");
        else if (i == 15 | i == 31)
          printf("\n");
        else
          printf(" ");
      }
      printf("\n");
    }
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}
