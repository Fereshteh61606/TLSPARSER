
#include <stdlib.h>
#include <stddef.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <memory.h>
#include <pcap.h>
#include "packet.h"
#include <string.h>
#include "tlsparser.h"







//====================================================================================================

int main()
{
    


    
    uint16_t offset = 0;
    Record_Header Record_Header;
    Handshake_Header handshake_header;
    TLS_Prameters tls_prameters;

    char error_buf[PCAP_ERRBUF_SIZE];
    memset(error_buf, 0, PCAP_ERRBUF_SIZE);
    pcap_t *handle = pcap_open_offline("../clienthello.pcap", error_buf);// pcap open
    if(handle==0){ 
#ifdef DBG       
        // P_ERROR(error_buf);
#endif
        return -1;
    };

    struct pcap_pkthdr *header;
    const uint8_t *data;
    int packet_count = 0;
        while (pcap_next_ex(handle, &header, &data) >= 0) {  
#ifdef DBG
            printf("LINE: %d, header.caplen: %u\n", __LINE__, header->caplen);
            printf("LINE: %d, header.len: %u\n", __LINE__, header->len);
            printf("Packet %d:\n", ++packet_count);
#endif
            packet_t pkt;
            pkt.bytes = data;
            pkt.byte_len = header->len;
            #ifdef DBF
            printf("LINE: %d, pkt.bytes: %p\n", __LINE__, pkt.bytes);
            printf("LINE: %d, pkt.len: %u\n", __LINE__, pkt.byte_len);
#endif            
            int ret = process_packet(&pkt);
            if(!pkt.payload_len)
                continue;
            if(!ret){
                 parse_TLS(pkt.payload, offset,pkt.byte_len, &Record_Header, &handshake_header, &tls_prameters);

   } 
        }
    pcap_close(handle);
    return 0;
}
