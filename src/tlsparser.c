#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <endian.h>
#include "tlsparser.h"
#include "packet.h"
#include <stdio.h>
#include <memory.h>


uint16_t parse_record_header(uint8_t *payload, uint16_t payload_len, Record_Header *record_header, uint16_t offset, TLS_Prameters *tls_prameters)
{
    if (payload_len > offset + 4)
    {

        // header start
        tls_prameters->state = 1;
        // Extract Type
        record_header->Content_Type = payload[offset];

        // Extract Version
        record_header->Legacy_version = (payload[offset + 1] << 8) | payload[offset + 2];

        // Extract message length
        record_header->Length = (payload[offset + 3] << 8) | payload[offset + 4];

        offset += 4;
        return offset;
    }

    else
    {
        tls_prameters->state = 0;
        return 0;
    }
}

//================================================================================================

uint16_t parse_handshke_header(uint8_t *payload, uint16_t payload_len, Handshake_Header *handshake_header, uint16_t offset, TLS_Prameters *tls_prameters)
{
    if (payload_len > offset + 4)
    {
        tls_prameters->state = 1;
        // header start

        // Extract Type
        handshake_header->type = payload[offset + 1];

        // Extract Version, boundry check
        handshake_header->length = (payload[offset + 2] << 16) | (payload[offset + 3] << 8) | payload[offset + 4];

        offset += 4;
        return offset;
    }

    else
    {
        tls_prameters->state = 0;
        return 0;
    }
}

//=================================================================================================================
uint16_t parse_client_hello(uint8_t *payload, uint16_t offset, uint16_t payload_len, TLS_Prameters *tls_prameters)
{
    offset += 2 + 32; // Version 2 B +random 32 B

    if (payload_len > offset + 1)
    {
        tls_prameters->state = 1;

        uint16_t ID_length = payload[offset + 1];
        offset += ID_length + 1; // 1B Idlen
    }
    else
    {
        tls_prameters->state = 0;
        return 0;
    }

    if (payload_len > offset + 2)
    {
        tls_prameters->state = 1;
        while (!((payload[offset + 1] == 0) && (payload[offset + 2] == 0)))
        {
            offset += 2;
        }
    }
    else
    {
        tls_prameters->state = 0;
        return 0;
    }

    tls_prameters->SNI_len = ((payload_len > offset + 9) ? (payload[offset + 8] << 8) | payload[offset + 9] : 0); //  00 00 assigned value for extension "server name" , +
                                                                                                                  // 2B extention data len+ 2B len of first (and only) list entry follows + 1B entry Type
    offset += 9;
    if (payload_len > offset + tls_prameters->SNI_len)
    {

        offset++;
        memcpy(tls_prameters->SNI, payload + offset, tls_prameters->SNI_len);

        offset += tls_prameters->SNI_len;

        return offset;
    }
    else
    {
        tls_prameters->state = 0;
        return 0;
    }
}
//=====================================================================================================================
void find_common_name(uint8_t *payload, uint16_t offset, uint16_t payload_len, TLS_Prameters *tls_prameters)
{

    if (payload_len > offset + 5)
    {
        tls_prameters->state = 1;
        while (!((payload[offset + 1] == 0x55) && (payload[offset + 2] == 0x04) && (payload[offset + 3] == 0x03)))
        {
            offset += 3;
        }

        tls_prameters->common_name_len = payload[offset + 5];
    }
    else

    {
        tls_prameters->state = 0;
        return;
    }

    offset += 5;
    if (payload_len > offset + tls_prameters->common_name_len)
    {
        tls_prameters->state = 1;
        offset++;
        memcpy(tls_prameters->common_name, payload + offset, tls_prameters->common_name_len);
        offset += tls_prameters->common_name_len;

        return;
    }
    else

    {
        tls_prameters->state = 0;
        return;
    }
}

//================================================================================================================================
bool parse_tls_data(uint8_t *payload, uint16_t payload_len, Handshake_Header *handshake_header, uint16_t offset, TLS_Prameters *tls_prameters)
{

    switch (handshake_header->type)
    {
        // Extensions Length
    case HANDSHAKE_TYPE_CLIENT_HELLO:
        offset = parse_client_hello(payload, offset, payload_len, tls_prameters);
        return 1;

    case HANDSHAKE_TYPE_SERVER_HELLO:
    case HANDSHAKE_TYPE_CERTIFICATE:
        find_common_name(payload, offset, payload_len, tls_prameters);
        return 1;
    default:
        return 0;
    }
}

//===========================================================================================================
void parse_TLS(uint8_t *payload, uint16_t offset, uint16_t payload_len, Record_Header *record_header, Handshake_Header *handshake_header, TLS_Prameters *tls_prameters)
{

    uint16_t indx = 0;
    bool continue_parsing = 0;
    while (indx < payload_len)
    {

        offset = parse_record_header(payload, payload_len, record_header, offset, tls_prameters);
        offset = parse_handshke_header(payload, payload_len, handshake_header, offset, tls_prameters);
        continue_parsing = parse_tls_data(payload, payload_len, handshake_header, offset, tls_prameters);
        if (continue_parsing)
            return;

        if (payload_len > record_header->Length)
        {
            indx += record_header->Length;
        }
        else
        {
            indx = payload_len;
        }
    }
}