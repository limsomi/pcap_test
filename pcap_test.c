#include <arpa/inet.h>
#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define ETHER_ADDR_LEN 6
void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

struct libnet_ethernet_hdr//enthernet header
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN]; /* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN]; /* source ethernet address */
    u_int16_t ether_type;                  /* protocol */
};

struct libnet_ipv4_hdr//ipv4 header
{
    u_int8_t ip_hl:4;
    u_int8_t ip_v:4;
    u_int8_t ip_tos;       /* type of service */
    u_int16_t ip_len;      /* total length */
    u_int16_t ip_id;       /* identification */
    u_int16_t ip_off;
    u_int8_t ip_ttl;       /* time to live */
    u_int8_t ip_p;         /* protocol */
    u_int16_t ip_sum;      /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct libnet_tcp_hdr// tcp header
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */

    u_int8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */


    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR   
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void print_mac(uint8_t *m){
    printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

int main(int argc, char* argv[]) 
{
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) 
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) 
    {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);//bring a packet
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)//if bringing a packet is wrong,...
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));//print error message
            break;
        }

        printf("===========================\n");
        printf("%u bytes captured\n", header->caplen);//print total length

        //extract ethernet header to packet//
        struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
        int ethernetHL = sizeof(struct libnet_ethernet_hdr);//ethernet header length
        
        //extract ipv4 header to packet//
        struct libnet_ipv4_hdr* ipv4_hdr = (struct libnet_ipv4_hdr*)(packet + ethernetHL);
        int ipHL = (ipv4_hdr->ip_hl & 0x0F) * 4;//ip header length
        
        //extract tcp header to packet//
        struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + ethernetHL + ipHL);
        int tcpHL=tcp_hdr->th_off*4;//tcp header length
        
        //extract payload to packet//    
        unsigned char* payload = (unsigned char*)(packet + ethernetHL + ipHL + tcpHL);
        int payloadLength = (int)header->caplen - (ethernetHL + ipHL + tcpHL);//caculate payload length
        
        //print packet information
        printf("smac : ");
        print_mac(eth_hdr->ether_shost);
        printf("\n");
        printf("dmac : ");
        print_mac(eth_hdr->ether_dhost);
        printf("\n");

        printf("src ip : %s\n", inet_ntoa(ipv4_hdr->ip_src));
        printf("dst ip : %s\n", inet_ntoa(ipv4_hdr->ip_dst));
        printf("src port : %d\n", ntohs(tcp_hdr->th_sport));
        printf("dst port : %d\n", ntohs(tcp_hdr->th_dport));

        if (payloadLength != 0) 
        {//print payload
            printf("payload : ");
            int i = 0;
            while (i < payloadLength && i < 10) 
            {
                printf("%02x", payload[i]);
                i++;
                if (i % 2 == 0) 
                {
                    printf(" ");
                }
            }
            printf("\n");
        }
        

    }
    pcap_close(pcap);
}
