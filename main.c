#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <memory.h>

#define max_servername_len 255

enum contentType
{
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    Application = 23,
    Heartbeat = 24

};

enum version
{
    SSL_3 = 0,
    TLS_1_0 = 1,
    TLS_1_1 = 2,
    TLS_1_2 = 3,
    TLS_1_3 = 4

};

enum HandshakeType
{
    hello_request = 0,
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_request = 13,
    certificate_verify = 15,
    finished = 20,
    key_update = 24

};

typedef struct Record_Header
{
    uint16_t Content_Type;
    uint16_t Legacy_version;
    uint16_t Length;

} RecordHeader;

typedef struct Handshake_Header
{

    uint16_t type;
    uint16_t length;

} Handshake_Header;

// typedef struct ClientHello
typedef struct TLSPrameters
{

    uint16_t Client_Version;
    char SNI[max_servername_len]; //(Server Name Indication
    char common_name[max_servername_len];
} TLSPrameters;

//================================================================================================

// Parsing the header
uint8_t parse_Record_header(uint8_t *payload, uint8_t payload_len, RecordHeader *Rhdr, uint8_t offset)
{
    if (payload_len > 5)
    {
        // header start

        // Extract Type
        Rhdr->Content_Type = payload[offset];

        // Extract Version
        Rhdr->Legacy_version = (payload[offset + 1] << 8) | payload[offset + 2];

        // Extract message length
        Rhdr->Length = (payload[offset + 3] << 8) | payload[offset + 4];

        offset += 5;
        return offset;
    }

    else
    {
        return -1;
    }
}

//================================================================================================

// Parsing the header
uint8_t parse_Handshke_header(uint8_t *payload, uint8_t payload_len, Handshake_Header *Hhdr, uint8_t offset)
{
    if (payload_len > 9)
    {
        // header start

        // Extract Type
        Hhdr->type = payload[offset];

        // Extract Version
        Hhdr->length = (payload[offset + 1] << 16) | (payload[offset + 2] << 8) | payload[offset + 3];

        offset += 4;
        return offset;
    }

    else
    {
        return -1;
    }
}

uint8_t clientHello(uint8_t *payload, uint8_t offset, char *Name, uint16_t *len)
{
    offset += 2 + 32; // Version 2 B +random 32 B
    uint8_t ID_length = payload[offset];
    offset += ID_length + 1;
    // uint8_t ciphersuit_length=  (payload[offset] << 8) | payload[offset + 1];
    // offset+=ciphersuit_length+2;
    while (!((payload[offset] == 0) && (payload[offset + 1] == 0)))
    {
        offset += 2;
    }
    uint8_t SNI_length = (payload[offset + 7] << 8) | payload[offset + 8]; //  00 00 assigned value for extension "server name" , +
                                                                         //2B extention data len+ 2B len of first (and only) list entry follows + 1B entry Type
    offset += 9;
    int j = 0;
    for (int i = offset; i < SNI_length + offset; ++i, ++j)
    {
        Name[j] = payload[i];
        // mydata[idx].RDATA[j] = *(p + i + 1);
    }
    offset += j;
    return offset;
}

void parsTLS(uint8_t *payload, uint8_t payload_len, Handshake_Header *Hhdr, uint8_t offset, char *Name, uint16_t *len)
{

    switch (Hhdr->type)
    {
        // Extensions Length
    case client_hello:
        offset = clientHello(payload, offset, Name, len);
        break;

    default:
        break;
    }
}

//===========================================================================================================



//================================================================================================

uint16_t uint16maker(uint8_t *payload, uint8_t offset)
{
    uint16_t result = (payload[offset] << 8) | payload[offset + 1];

    return result;
}

//====================================================================================================

int main()
{

    uint8_t payload[] =
        {
            0x16, 0x03, 0x01, 0x00, 0xf8, 0x01, 0x00, 0x00, 0xf4, 0x03, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x00, 0x08, 0x13, 0x02, 0x13, 0x03, 0x13, 0x01, 0x00, 0xff, 0x01, 0x00, 0x00, 0xa3, 0x00, 0x00, 0x00, 0x18, 0x00, 0x16, 0x00, 0x00, 0x13, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x75, 0x6c, 0x66, 0x68, 0x65, 0x69, 0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x0a, 0x00, 0x16, 0x00, 0x14, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00, 0x19, 0x00, 0x18, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04, 0x00, 0x23, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x1e, 0x00, 0x1c, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08, 0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x35, 0x80, 0x72, 0xd6, 0x36, 0x58, 0x80, 0xd1, 0xae, 0xea, 0x32, 0x9a, 0xdf, 0x91, 0x21, 0x38, 0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e, 0x3b, 0x75, 0xe9, 0x65, 0xd0, 0xd2, 0xcd, 0x16, 0x62, 0x54};

    uint8_t payload_len = sizeof(payload);
    uint8_t offset = 0;
    RecordHeader Rhdr;
    Handshake_Header Hhdr;
    char Name[max_servername_len];
    uint16_t len;

    offset = parse_Record_header(payload, payload_len, &Rhdr, offset);
    offset = parse_Handshke_header(payload, payload_len, &Hhdr, offset);
    parsTLS(payload, payload_len, &Hhdr, offset, Name, &len);

    return 0;
}
