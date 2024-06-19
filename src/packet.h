#ifndef PKT_H_
#define PKT_H_
#pragma ONCE
#include <stdbool.h>
#include <stdint.h>

typedef struct packet packet_t;

enum IP_VERSION
{
    IPV4, IPV6
};

enum TRANS_PROTO
{
    TCP, UDP, ICMP, SCTP, OTHER
};

struct packet
{
    uint8_t* bytes;
    uint16_t byte_len;
    enum TRANS_PROTO trans_proto;
    uint8_t* payload;
    uint16_t payload_len;
    uint16_t sport, dport;
    bool is_malformed;
};
int process_packet(struct packet* pkt);


#endif