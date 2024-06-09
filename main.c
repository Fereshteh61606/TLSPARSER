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

        offset += 4;
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
        Hhdr->type = payload[offset + 1];

        // Extract Version
        Hhdr->length = (payload[offset + 2] << 16) | (payload[offset + 3] << 8) | payload[offset + 4];

        offset += 4;
        return offset;
    }

    else
    {
        return -1;
    }
}


void parsTLS(uint8_t *payload, uint8_t payload_len, Handshake_Header *Hhdr, uint8_t offset, char *Name, uint16_t *len)
{

    switch (Hhdr->type)
    {
Extensions Length
    case client_hello:
        offset += 2 + 32; // Version +random
        uint8_t ID_length = payload[offset];
        offset += ID_length + 1;
        // uint8_t ciphersuit_length=  (payload[offset] << 8) | payload[offset + 1];
        // offset+=ciphersuit_length+2;
        while ((payload[offset]) && payload[offset + 1] != 0)
        {
            offset += 1;
        }
        uint8_t SNI_length = payload[offset + 6];
        int j = 0;
        for (int i = offset; i < SNI_length + offset; ++i, j++)
        {
            Name[j] = payload[i];
            // mydata[idx].RDATA[j] = *(p + i + 1);
        }

    default:
        break;
    }
}

//===========================================================================================================

// Acquiring the  th Domain name
// int dnsReadName(uint8_t *payload, int payloadLen, uint8_t *ptr)
// uint8_t dnsReadName(uint8_t *payload, uint8_t offset, Query *myquery)
uint8_t dnsReadName(uint8_t *payload, uint8_t offset, char *Name, uint16_t *len)

{

    // uint8_t *p = ptr;

    // while (p < end)
    //{

    uint8_t label_len = payload[offset];

    uint8_t j = 0;
    // mydata[idx].RDATA=&mydata[idx].DomainName[max_DNS_domain_len]+1;
    while (payload[offset] != 0)
    {

        label_len = payload[offset];
        offset += 1;
        for (int i = offset; i < label_len + offset; ++i, j++)
        {
            Name[j] = payload[i];
            // mydata[idx].RDATA[j] = *(p + i + 1);
        }
        offset += label_len;

        Name[j] = '.';
        // mydata[idx].RDATA[j] = '.';
        ++j;
    }
    Name[j - 1] = '\0';
    *len = j + 1;
    // }
    // ptr = p;
    offset += 1;
    return offset; // namelength
}

//================================================================================================

//================================================================================================

uint16_t uint16maker(uint8_t *payload, uint8_t offset)
{
    uint16_t result = (payload[offset] << 8) | payload[offset + 1];

    return result;
}
//======================================================================================================

//======================================================================================================
// Reading RRs

// void parse_DNS_RRs(uint8_t *payload, int payloadLen, uint8_t *ptr, DNSData *mydata, DNSHeader *hdr)
// void parse_DNS_RRs(uint8_t *payload, int payloadLen, uint8_t offset, DNSData *mydata, DNSHeader *hdr)
uint8_t parse_TLS(uint8_t *payload, uint8_t offset, DNSData *mydata, DNSHeader *hdr, uint8_t payload_len)
{

    //++++++++++++++++++++++++++++++++++++++++++++++Answer++++++++++++++++++++++++++++++++++++
    int i = 0;
    uint8_t comp_offset;

    char transfer_type = 'U';

    u_int16_t Answercount = hdr->cAnswers;

    while (Answercount > 0)
    {

        comp_offset = (((*(payload + offset) & 0xc0) == 0xc0) ? *(payload + offset + 1) : 0);

        if (comp_offset != 0)
        {
            int x = Check_Transfer(transfer_type);
            x = dnsReadName(payload, x + comp_offset, mydata->Name, &mydata->Name_len);
            offset += 2;
        }
        // read data section

        mydata[i].type = uint16maker(payload, offset);
        offset += 2;
        mydata[i].class = uint16maker(payload, offset);
        offset += 2;
        // mydata[i].TTL = (uint16maker(payload, offset) << 16 | uint16maker(payload, offset + 2));
        offset += 4;
        mydata[i].datalen = uint16maker(payload, offset);
        offset += 2;
        mydata[i].RDATA = malloc(mydata[i].datalen * 2);
        offset += mydata[i].datalen;

        // mydata=mydata+10+mydata[i].datalen;
        // mydata[i].RDATA= mydata+10+mydata[i].datalen;
        //  ptr += 9;
        //  bool isreverse;
        //   isreverse = ((hdr->Flags | 0x7800) ? true : false);

        switch (mydata[i].type)
        {
        case DNS_RRs_TYPE_CNAME:
        {

            memcpy(mydata[i].RDATA, &mydata->Name, mydata->Name_len);

            break;
        }
        case DNS_RRs_TYPE_A:
        {

            inet_ntop(AF_INET, payload + offset, mydata[i].RDATA, INET_ADDRSTRLEN);
            printf("\n Rdata: %s \n", mydata[i].RDATA);
            break;

            // inet_ntop(AF_INET, &payload[offset], mydata->RDATA, INET_ADDRSTRLEN);
        }

        case DNS_RRs_TYPE_AAAA:
        {

            inet_ntop(AF_INET6, payload + offset, mydata[i].RDATA, INET6_ADDRSTRLEN);

            // struct in_addr ip6_addr;

            // inet_ntop(AF_INET6, &payload[offset], mydata->RDATA, INET6_ADDRSTRLEN);
            break;
        }
        default:
            break;
        }

        i++;
        Answercount--;
    }
    return offset;
}

//====================================================================================================

int main()
{

    uint8_t payload[] =
        {
            0x6a, 0xe7, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x03, 0x77, 0x77, 0x77,
            0x06, 0x61, 0x70, 0x61, 0x72, 0x61, 0x74, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x14, 0x62, 0x00, 0x04, 0xb9, 0x93, 0xb2, 0x0b,
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x14, 0x62, 0x00, 0x04, 0xb9, 0x93, 0xb2, 0x0c,
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x14, 0x62, 0x00, 0x04, 0xb9, 0x93, 0xb2, 0x0d,
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x14, 0x62, 0x00, 0x04, 0xb9, 0x93, 0xb2, 0x0e,
            0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 00};

    uint8_t payload_len = sizeof(payload);
    uint8_t offset;
    DNSHeader hdr;

    offset = parse_DNS_header(payload, payload_len, &hdr, offset);
    DNSData *mydata = malloc((hdr.cAnswers) * sizeof(DNSData)); // [hdr.cAnswers + 1]; // undefined behaviour

    return 0;
}
