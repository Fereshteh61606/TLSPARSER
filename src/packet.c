#define _DEFAULT_SOURCE 1
#define _BSD_SOURCE 1

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <endian.h>
#include <stdint.h>
#include "packet.h"
#include <stdio.h>

static int process_layer4(packet_t* pkt, uint16_t offset, uint8_t proto);

int process_packet(struct packet* pkt)
{
    struct ether_header* eth_hdr = (struct ether_header*)(pkt->bytes);

    uint16_t etype = be16toh(eth_hdr->ether_type);

    if(etype == ETH_P_IP)
    {
        struct iphdr* ip_hdr = (struct ip*)(pkt->bytes + sizeof(struct ether_header));
        int ret = process_layer4(pkt, ip_hdr->ihl * 4 + sizeof(struct ether_header),ip_hdr->protocol);
        if (ret)
            return 1;

    }
    else if(etype == ETH_P_IPV6)
    {
        struct ip6_hdr* ipv6_hdr = (struct ip6_hdr*)(pkt->bytes + sizeof(struct ether_header));
        int ret = process_layer4(pkt, sizeof(struct ip6_hdr) + sizeof(struct ether_header), ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt);
        if (ret)
            return 1;
    }
    else
    {
        return 1; 
    }
    return 0;
}

int process_layer4(packet_t* pkt, uint16_t offset, uint8_t proto)
{
    if(proto == IPPROTO_TCP)
    {
        struct tcphdr* tcp_hdr = (struct tcphdr*)(pkt->bytes + offset);
        pkt->trans_proto = TCP;
        int x=sizeof(tcp_hdr);
       
        offset+=(sizeof(tcp_hdr)*4);
        pkt->payload = pkt->bytes + offset;
        pkt->payload_len = pkt->byte_len - offset;
        if(!pkt->payload_len){
#ifdef DBG
        printf("LINE: %d, A Problem in assigning pointer\n", __LINE__);
#endif
        return 1;
        }
        uint16_t dport = be16toh(tcp_hdr->dest);
        uint16_t sport = be16toh(tcp_hdr->source);

        if((dport != 443) & (sport !=443) )
            return 1;
    }
    else if(proto == IPPROTO_UDP)
    {
        struct udphdr* udp_hdr = (struct udphdr*)(pkt->bytes + offset);
        pkt->trans_proto = UDP;
        pkt->payload = pkt->bytes + offset + sizeof(struct udphdr);
        pkt->payload_len = pkt->byte_len - (offset + sizeof(struct udphdr));
        if(!pkt->payload_len){
#ifdef DBG
        printf("LINE: %d, A Problem in assigning pointer\n", __LINE__);
#endif
        return 1;
        }
        uint16_t dport = be16toh(udp_hdr->uh_dport);
        uint16_t sport = be16toh(udp_hdr->uh_sport);
        if((dport != 53) & (sport !=53) )
            return 1;

    }
    else{
        return 1;
    }

    return 0;
}
