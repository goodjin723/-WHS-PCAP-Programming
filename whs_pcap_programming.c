#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>

/* Ethernet Header */

struct ethheader {
	u_char ether_dhost[6]; // destination MAC
	u_char ether_shost[6]; // source MAC
	u_short ether_type;    // protocol type
};

/* IP Header */
struct ipheader {
	unsigned char iph_ihl:4, iph_ver:4; // IP header length, IP version
	unsigned char iph_tos;              // Type of service
	unsigned short int iph_len;         // IP Packet length (data+length)
	unsigned short int iph_ident;       // Identification
	unsigned short int iph_flag:3, iph_offset:13; // Fragmentation flags, Flags offset
	unsigned char iph_ttl;              // Time to Live
	unsigned char iph_protocol;         // Protocol type
	unsigned short int iph_chksum;      // IP datagram checksum
	struct in_addr iph_sourceip;  // Source IP address
	struct in_addr iph_destip;    // Destination IP address
};

/* TCP Header */
struct tcpheader {
	u_short tcp_sport;
	u_short tcp_dport;
	u_int32_t tcp_seq;
	u_int32_t tcp_ack;
	u_char tcp_offx2;
	u_char tcp_flags;
	u_short tcp_win;
	u_short tcp_sum;
	u_short tcp_urp;
};

void print_MAC(const u_char *mac)
{
	for(int i=0; i<6; ++i) {
		printf("%02x", mac[i]);
		if (i != 5) printf(":");
	}
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader));
                           
    if (ip->iph_protocol != IPPROTO_TCP) return; // Only TCP
    
    int ip_header_len = ip->iph_ihl * 4;
    struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + ip_header_len);
    int tcp_header_len = ((tcp->tcp_offx2 & 0xF0) >> 4) * 4;
    
    int total_header_size = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
    int total_packet_size = header->caplen;
    int message_size = total_packet_size - total_header_size;
    
    const u_char *message = packet + total_header_size;
    
    
    printf("\n*** Packet Captured ***\n");
    
    printf("Ether Header - Src MAC: ");
    print_MAC(eth->ether_shost);
    printf("\n");
    
    printf("Ether Header - Dst MAC: ");
    print_MAC(eth->ether_dhost);
    printf("\n");
    
    printf("IP Header - Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("IP Header - Dst IP: %s\n", inet_ntoa(ip->iph_destip));
    
    printf("TCP Header - Src Port: %d\n", ntohs(tcp->tcp_sport));
    printf("TCP Header - Dst Port: %d\n", ntohs(tcp->tcp_dport));
    
    if(message_size > 0){
        printf("\n=== HTTP Message ===\n");
    	for (int i=0; i<message_size; i++) {
    		if (message[i] == '\n') printf("\n");
    		else if (isprint(message[i])) printf("%c", message[i]);
    		else printf(".");
    	}
   	printf("\n====================\n");
    }

  }
}
    
int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}

