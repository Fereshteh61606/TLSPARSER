#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <memory.h>

#define MAX_NAME_LEN 255

enum CONTENTTYPE
{
    CONTENTTYPE_CHANGECIPHERSPEC = 20,
    CONTENTTYPE_CALERT = 21,
    CONTENTTYPE_CHANDSHAKE = 22,
    CONTENTTYPE_CAPPLICATION = 23,
    CONTENTTYPE_CHEARTBEAT = 24

};

enum VERSION
{
    VERSION_SSL_3 = 0,
    VERSION_TLS_1_0 = 1,
    VERSION_TLS_1_1 = 2,
    VERSION_TLS_1_2 = 3,
    VERSION_TLS_1_3 = 4

};

enum HANDSHAKE_TYPE
{
    HANDSHAKE_TYPE_HELLO_REQUEST = 0,
    HANDSHAKE_TYPE_CLIENT_HELLO = 1,
    HANDSHAKE_TYPE_SERVER_HELLO = 2,
    HANDSHAKE_TYPE_NEW_SESSION_TICKET = 4,
    HANDSHAKE_TYPE_END_OF_EARLY_DATA = 5,
    HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = 8,
    HANDSHAKE_TYPE_CERTIFICATE = 11,
    HANDSHAKE_TYPE_CERTIFICATE_REQUEST = 13,
    HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 15,
    HANDSHAKE_TYPE_FINISHED = 20,
    HANDSHAKE_TYPE_KEY_UPDATE = 24

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

    uint16_t Name_len;
    char Name[MAX_NAME_LEN]; //(Server Name Indication or Common name

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

        // Extract Version, boundry check
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
    while (!((payload[offset] == 0) && (payload[offset + 1] == 0)))
    {
        offset += 2;
    }
    uint8_t SNI_length = (payload[offset + 7] << 8) | payload[offset + 8]; //  00 00 assigned value for extension "server name" , +
                                                                           // 2B extention data len+ 2B len of first (and only) list entry follows + 1B entry Type
    offset += 9;
    int j = 0;
    for (int i = offset; i < SNI_length + offset; ++i, ++j)
    {
        Name[j] = payload[i];
    }
    offset += j;
    *len = j;
    return offset;
}

uint8_t find_common_name(uint8_t *payload, uint8_t offset, char *Name, uint16_t *len)
{
    while (!((payload[offset] == 85) && (payload[offset + 1] == 4) && (payload[offset + 2] == 3)))
    {
        offset += 3;
    }

    uint8_t common_name_len = payload[offset + 4];
    offset += 4;

    int j = 0;
    for (int i = offset; i < common_name_len + offset; ++i, ++j)
    {
        Name[j] = payload[i];
    }
    offset += j;
    *len = j;
    return offset;
}

uint8_t pars_TLS(uint8_t *payload, uint8_t payload_len, Handshake_Header *Hhdr, uint8_t offset, char *Name, uint16_t *len)
{

    switch (Hhdr->type)
    {
        // Extensions Length
    case HANDSHAKE_TYPE_CLIENT_HELLO:
        offset = clientHello(payload, offset, Name, len);
        return offset;

    default:
        offset = find_common_name(payload, offset, Name, len);
        return offset;
    }
}

//===========================================================================================================
void start_parsing(uint8_t *payload, uint8_t offset, uint16_t payload_len, uint16_t *indx)
{
    RecordHeader Rhdr;
    Handshake_Header Hhdr;
    char Name[MAX_NAME_LEN];
    uint16_t len;

    offset = parse_Record_header(payload, payload_len, &Rhdr, offset);
    offset = parse_Handshke_header(payload, payload_len, &Hhdr, offset);
    offset = pars_TLS(payload, payload_len, &Hhdr, offset, Name, &len);

    TLSPrameters mypram;
    memcpy(mypram.Name, Name, len);
    mypram.Name_len = len;
    *indx = Rhdr.Length;
}

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
  0x16, 0x03, 0x03, 0x0f, 0x10, 0x02, 0x00, 0x00,
  0x5a, 0x03, 0x03, 0x60, 0xed, 0x5b, 0x0d, 0xad,
  0x41, 0xef, 0xed, 0xa2, 0xbc, 0x9b, 0x9d, 0x5e,
  0xc4, 0xb0, 0xa0, 0x6f, 0xd5, 0x17, 0x81, 0xe8,
  0x56, 0x76, 0xbc, 0x1a, 0x6a, 0xc8, 0xea, 0xfe,
  0x46, 0x47, 0xb9, 0x20, 0x4a, 0x45, 0x00, 0x00,
  0x24, 0x01, 0x4c, 0x3b, 0xff, 0xfd, 0x12, 0xe7,
  0x08, 0x8a, 0xcd, 0x7d, 0x5f, 0xa1, 0x23, 0xdb,
  0x20, 0xbd, 0x4c, 0xd1, 0x33, 0x67, 0xbb, 0x17,
  0xea, 0x03, 0x31, 0xc9, 0xc0, 0x30, 0x00, 0x00,
  0x12, 0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02,
  0x68, 0x32, 0x00, 0x17, 0x00, 0x00, 0xff, 0x01,
  0x00, 0x01, 0x00, 0x0b, 0x00, 0x0d, 0x3d, 0x00,
  0x0d, 0x3a, 0x00, 0x06, 0x58, 0x30, 0x82, 0x06,
  0x54, 0x30, 0x82, 0x04, 0x3c, 0xa0, 0x03, 0x02,
  0x01, 0x02, 0x02, 0x13, 0x33, 0x00, 0x00, 0x01,
  0xa1, 0x14, 0xd9, 0xa2, 0xe0, 0x18, 0xf6, 0x64,
  0xd8, 0x00, 0x00, 0x00, 0x00, 0x01, 0xa1, 0x30,
  0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
  0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x7e,
  0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
  0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30,
  0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x0a,
  0x57, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x74,
  0x6f, 0x6e, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03,
  0x55, 0x04, 0x07, 0x13, 0x07, 0x52, 0x65, 0x64,
  0x6d, 0x6f, 0x6e, 0x64, 0x31, 0x1e, 0x30, 0x1c,
  0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x15, 0x4d,
  0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74,
  0x20, 0x43, 0x6f, 0x72, 0x70, 0x6f, 0x72, 0x61,
  0x74, 0x69, 0x6f, 0x6e, 0x31, 0x28, 0x30, 0x26,
  0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x1f, 0x4d,
  0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74,
  0x20, 0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x20,
  0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x43,
  0x41, 0x20, 0x32, 0x30, 0x31, 0x31, 0x30, 0x1e,
  0x17, 0x0d, 0x32, 0x30, 0x31, 0x32, 0x31, 0x30,
  0x31, 0x39, 0x33, 0x38, 0x32, 0x38, 0x5a, 0x17,
  0x0d, 0x32, 0x32, 0x30, 0x33, 0x31, 0x30, 0x31,
  0x39, 0x33, 0x38, 0x32, 0x38, 0x5a, 0x30, 0x81,
  0x91, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
  0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13,
  0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13,
  0x0a, 0x57, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67,
  0x74, 0x6f, 0x6e, 0x31, 0x10, 0x30, 0x0e, 0x06,
  0x03, 0x55, 0x04, 0x07, 0x13, 0x07, 0x52, 0x65,
  0x64, 0x6d, 0x6f, 0x6e, 0x64, 0x31, 0x1e, 0x30,
  0x1c, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x15,
  0x4d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66,
  0x74, 0x20, 0x43, 0x6f, 0x72, 0x70, 0x6f, 0x72,
  0x61, 0x74, 0x69, 0x6f, 0x6e, 0x31, 0x1e, 0x30,
  0x1c, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x15,
  0x4d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66,
  0x74, 0x20, 0x43, 0x6f, 0x72, 0x70, 0x6f, 0x72,
  0x61, 0x74, 0x69, 0x6f, 0x6e, 0x31, 0x1b, 0x30,
  0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x12,
  0x77, 0x64, 0x63, 0x70, 0x2e, 0x6d, 0x69, 0x63,
  0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x2e, 0x63,
  0x6f, 0x6d, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d,
  0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
  0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01,
  0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82,
  0x01, 0x01, 0x00, 0xe9, 0x07, 0x26, 0x58, 0x16,
  0xad, 0x2c, 0xc0, 0x16, 0xb5, 0xfc, 0xdc, 0xec,
  0xfb, 0x25, 0xf7, 0xf7, 0x35, 0x58, 0x3d, 0xea,
  0x10, 0x90, 0x67, 0xaf, 0x48, 0x7b, 0x11, 0xee,
  0xa6, 0x3d, 0x06, 0x93, 0x3c, 0x22, 0x5e, 0x14,
  0x08, 0x3b, 0xbd, 0x5f, 0x2a, 0x4a, 0xfb, 0x2a,
  0xa9, 0xb5, 0x59, 0xc8, 0xac, 0x63, 0xcf, 0xdb,
  0x3c, 0x44, 0x82, 0x11, 0x1c, 0x68, 0x79, 0xc9,
  0xe3, 0xac, 0x45, 0xcf, 0xe7, 0x10, 0xbe, 0x9d,
  0x6c, 0x01, 0x67, 0x6c, 0x40, 0x19, 0xc4, 0xb6,
  0xc5, 0xfd, 0xa5, 0x0d, 0xf6, 0xf7, 0xa2, 0x33,
  0xec, 0x70, 0xbf, 0x0f, 0x3a, 0x21, 0x40, 0xa9,
  0x96, 0x47, 0x00, 0x11, 0xcc, 0x27, 0x5d, 0xfb,
  0xc5, 0x27, 0xb3, 0x12, 0xc8, 0xcf, 0xdf, 0xf5,
  0x15, 0x2b, 0xbf, 0xb6, 0xf6, 0x03, 0xf9, 0xa5,
  0x11, 0x27, 0xc6, 0x30, 0x1c, 0x58, 0x96, 0x4f,
  0xe0, 0xcd, 0xb9, 0x9a, 0x7b, 0x42, 0xc7, 0x0b,
  0x02, 0xbe, 0xa4, 0xb0, 0x19, 0x9a, 0xf1, 0xbd,
  0xb0, 0xef, 0xab, 0x37, 0x69, 0x4b, 0xc7, 0x0c,
  0x05, 0xe0, 0x6b, 0xe8, 0x81, 0xf7, 0x97, 0x53,
  0x78, 0xed, 0xfd, 0x22, 0x9b, 0x25, 0xa2, 0xbe,
  0x78, 0x4d, 0xa8, 0xd4, 0xe7, 0x9b, 0xe8, 0x27,
  0xbd, 0x51, 0x2e, 0xb7, 0xd0, 0xd0, 0x45, 0x8c,
  0x68, 0xc8, 0x24, 0x28, 0x35, 0x15, 0xf4, 0x07,
  0x08, 0xa1, 0x2e, 0x7e, 0xd7, 0x2a, 0x4a, 0xb2,
  0x83, 0x06, 0x4b, 0xe9, 0x73, 0xaa, 0xc8, 0x14,
  0x7c, 0x3d, 0x65, 0x31, 0x80, 0xe9, 0x8d, 0x45,
  0x9b, 0x6e, 0x69, 0xff, 0x84, 0x2a, 0x5c, 0xc7,
  0xa1, 0x55, 0xc5, 0x8c, 0x1d, 0x2a, 0x68, 0x7f,
  0x73, 0x71, 0xf7, 0x5e, 0x3e, 0x02, 0xd2, 0x2f,
  0x04, 0x21, 0x50, 0x2e, 0xdd, 0xe1, 0x0c, 0x7d,
  0x13, 0x7e, 0xc8, 0x03, 0x56, 0xea, 0x72, 0x1b,
  0x90, 0x8a, 0x75, 0x02, 0x03, 0x01, 0x00, 0x01,
  0xa3, 0x82, 0x01, 0xb5, 0x30, 0x82, 0x01, 0xb1,
  0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01,
  0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x05, 0xa0,
  0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04,
  0x16, 0x30, 0x14, 0x06, 0x08, 0x2b, 0x06, 0x01,
  0x05, 0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2b,
  0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x30,
  0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16,
  0x04, 0x14, 0x98, 0x66, 0x25, 0x12, 0xe0, 0x92,
  0xff, 0x84, 0x3c, 0x91, 0x73, 0xda, 0x3d, 0x94,
  0xe4, 0xfb, 0x01, 0xae, 0x1a, 0xba, 0x30, 0x7b,
  0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x74, 0x30,
  0x72, 0x82, 0x12, 0x77, 0x64, 0x63, 0x70, 0x2e,
  0x6d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66,
  0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x15, 0x73,
  0x70, 0x79, 0x6e, 0x65, 0x74, 0x32, 0x2e, 0x6d,
  0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74,
  0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x15, 0x77, 0x64,
  0x63, 0x70, 0x61, 0x6c, 0x74, 0x2e, 0x6d, 0x69,
  0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x2e,
  0x63, 0x6f, 0x6d, 0x82, 0x17, 0x73, 0x70, 0x79,
  0x6e, 0x65, 0x74, 0x61, 0x6c, 0x74, 0x2e, 0x6d,
  0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74,
  0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x15, 0x2a, 0x2e,
  0x63, 0x70, 0x2e, 0x77, 0x64, 0x2e, 0x6d, 0x69,
  0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x2e,
  0x63, 0x6f, 0x6d, 0x30, 0x1f, 0x06, 0x03, 0x55,
  0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,
  0x36, 0x56, 0x89, 0x65, 0x49, 0xcb, 0x5b, 0x9b,
  0x2f, 0x3c, 0xac, 0x42, 0x16, 0x50, 0x4d, 0x91,
  0xb9, 0x33, 0xd7, 0x91, 0x30, 0x53, 0x06, 0x03,
  0x55, 0x1d, 0x1f, 0x04, 0x4c, 0x30, 0x4a, 0x30,
  0x48, 0xa0, 0x46, 0xa0, 0x44, 0x86, 0x42, 0x68,
  0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77,
  0x77, 0x2e, 0x6d, 0x69, 0x63, 0x72, 0x6f, 0x73,
  0x6f, 0x66, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
  0x70, 0x6b, 0x69, 0x6f, 0x70, 0x73, 0x2f, 0x63,
  0x72, 0x6c, 0x2f, 0x4d, 0x69, 0x63, 0x53, 0x65,
  0x63, 0x53, 0x65, 0x72, 0x43, 0x41, 0x32, 0x30,
  0x31, 0x31, 0x5f, 0x32, 0x30, 0x31, 0x31, 0x2d,
  0x31, 0x30, 0x2d, 0x31, 0x38, 0x2e, 0x63, 0x72,
  0x6c, 0x30, 0x60, 0x06, 0x08, 0x2b, 0x06, 0x01,
  0x05, 0x05, 0x07, 0x01, 0x01, 0x04, 0x54, 0x30,
  0x52, 0x30, 0x50, 0x06, 0x08, 0x2b, 0x06, 0x01,
  0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x44, 0x68,
  0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77,
  0x77, 0x2e, 0x6d, 0x69, 0x63, 0x72, 0x6f, 0x73,
  0x6f, 0x66, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
  0x70, 0x6b, 0x69, 0x6f, 0x70, 0x73, 0x2f, 0x63,
  0x65, 0x72, 0x74, 0x73, 0x2f, 0x4d, 0x69, 0x63,
  0x53, 0x65, 0x63, 0x53, 0x65, 0x72, 0x43, 0x41,
  0x32, 0x30, 0x31, 0x31, 0x5f, 0x32, 0x30, 0x31,
  0x31, 0x2d, 0x31, 0x30, 0x2d, 0x31, 0x38, 0x2e,
  0x63, 0x72, 0x74, 0x30, 0x0c, 0x06, 0x03, 0x55,
  0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30,
  0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
  0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
  0x03, 0x82, 0x02, 0x01, 0x00, 0x80, 0x1c, 0xbe,
  0xe0, 0xdc, 0xa2, 0x5f, 0x3d, 0x7b, 0x1d, 0x64,
  0x62, 0xcb, 0xb8, 0x29, 0xb5, 0x0e, 0x47, 0xb4,
  0xa8, 0xc3, 0x3f, 0xd2, 0x8b, 0x2d, 0x85, 0x63,
  0x18, 0xe3, 0xdc, 0x24, 0x98, 0x60, 0xd7, 0xe9,
  0xf6, 0x38, 0xb1, 0x26, 0x09, 0x64, 0x04, 0xf5,
  0xc9, 0xa0, 0xd2, 0x8c, 0x50, 0x7b, 0xe6, 0xad,
  0x66, 0xdc, 0x30, 0xa1, 0x97, 0xf4, 0x18, 0xd4,
  0x4d, 0x7c, 0x56, 0x94, 0x66, 0xfa, 0x97, 0x3b,
  0xd4, 0x03, 0x20, 0xd8, 0x70, 0xf5, 0x91, 0xe1,
  0x7f, 0x17, 0xeb, 0xc8, 0xad, 0x44, 0x0f, 0x4b,
  0x19, 0xf7, 0xf7, 0x33, 0x96, 0x2f, 0x62, 0x4f,
  0xbb, 0x84, 0x34, 0xf8, 0x07, 0x85, 0x31, 0xe2,
  0xae, 0x83, 0x98, 0x8d, 0x71, 0x1d, 0x5c, 0x0a,
  0xdb, 0x98, 0x58, 0x5f, 0x44, 0x8a, 0x9e, 0x6f,
  0x28, 0xca, 0x8b, 0x58, 0xa3, 0xec, 0xe8, 0x4c,
  0x3b, 0x56, 0xaf, 0xe3, 0x8c, 0xda, 0xc4, 0xb3,
  0x94, 0x1f, 0x9d, 0x81, 0xb8, 0x83, 0x6c, 0x51,
  0x79, 0xe2, 0x3f, 0x8b, 0x60, 0x3d, 0xfb, 0x00,
  0x74, 0xc3, 0xad, 0x9e, 0xae, 0x33, 0x6b, 0xee,
  0xe4, 0xb6, 0xee, 0xe0, 0xb0, 0xee, 0xca, 0x3e,
  0x30, 0xca, 0x2a, 0xce, 0x12, 0xbb, 0x77, 0x4e,
  0x76, 0xf2, 0x4c, 0xc2, 0x52, 0xcc, 0xf7, 0xa3,
  0x17, 0x81, 0x2d, 0x74, 0xf9, 0x9d, 0xc2, 0x0c,
  0xf5, 0xf1, 0x45, 0x6a, 0x30, 0x7e, 0x2c, 0x2c,
  0x73, 0xbe, 0xdb, 0xf1, 0xc1, 0xea, 0x25, 0x30,
  0x2b, 0x13, 0x17, 0x6e, 0x2f, 0xfc, 0x1f, 0x18,
  0x9d, 0x9f, 0x22, 0xaa, 0x34, 0x9e, 0x10, 0x31,
  0x56, 0x5e, 0x4f, 0x98, 0x5a, 0x2b, 0x82, 0xc1,
  0x9d, 0x2a, 0x3c, 0x02, 0x8c, 0xfc, 0x3a, 0x6b,
  0x3e, 0x61, 0x73, 0xca, 0x5a, 0x5f, 0x3a, 0xfd,
  0x18, 0x66, 0x39, 0x07, 0xdd, 0x5f, 0x57, 0xa4,
  0xb6, 0xc5, 0xe2, 0xcf, 0x0f, 0xdc, 0x41, 0x69,
  0xa4, 0xc4, 0x8c, 0x70, 0xe3, 0xb6, 0xc4, 0x55,
  0x2e, 0x48, 0x52, 0x66, 0x3f, 0x39, 0x30, 0xad,
  0x37, 0x56, 0x72, 0xee, 0xe7, 0xf3, 0x3d, 0x81,
  0x19, 0x7b, 0x22, 0xf9, 0x6c, 0xd4, 0xe5, 0x67,
  0x28, 0x82, 0x4b, 0xc6, 0xfb, 0xdb, 0x70, 0x7f,
  0xe1, 0x0c, 0x5e, 0x47, 0x0a, 0x8a, 0x43, 0x8d,
  0xe7, 0xc8, 0x56, 0x42, 0x6c, 0xb1, 0x14, 0x29,
  0x0a, 0xc8, 0x86, 0xb3, 0x2b, 0x8e, 0x5b, 0x6b,
  0x93, 0xf2, 0xb6, 0x03, 0xd0, 0x14, 0xe3, 0x12,
  0x47, 0x7c, 0x18, 0x7f, 0x5c, 0xc6, 0xf5, 0x1f,
  0x2b, 0x06, 0x55, 0x8c, 0xa5, 0xac, 0xaf, 0xb4,
  0x76, 0x2a, 0xf5, 0x3b, 0xe0, 0x3f, 0xa4, 0xa0,
  0xd7, 0x60, 0x77, 0xb4, 0xba, 0xab, 0xe7, 0xd6,
  0x42, 0xb8, 0x16, 0x6f, 0x1d, 0xd2, 0xaa, 0x68,
  0xa0, 0x34, 0x5d, 0x72, 0xdf, 0xc1, 0x67, 0x09,
  0x08, 0x3d, 0xd3, 0x93, 0xd2, 0x5d, 0xad, 0xbe,
  0xdb, 0x9d, 0x3a, 0x9f, 0xef, 0xda, 0x16, 0xc1,
  0x0e, 0x64, 0xbc, 0x15, 0xda, 0xb3, 0xa4, 0xdd,
  0xee, 0xc1, 0x5f, 0x03, 0x6e, 0x5e, 0x36, 0x70,
  0x64, 0x00, 0xd7, 0xc5, 0x93, 0x6f, 0xd2, 0x45,
  0x1f, 0xda, 0x66, 0x67, 0xee, 0x49, 0x64, 0x0d,
  0x88, 0xc3, 0xc6, 0x54, 0xfb, 0x04, 0x5a, 0x11,
  0xe6, 0x2d, 0xd9, 0xcd, 0x97, 0x00, 0xd6, 0x1e,
  0x11, 0x51, 0xcf, 0x30, 0x1f, 0x66, 0xa4, 0x36,
  0x67, 0x5f, 0x72, 0xf0, 0x2e, 0xde, 0x99, 0xeb,
  0xed, 0xc0, 0xa6, 0x2b, 0xbb, 0x4c, 0x42, 0x61,
  0x88, 0xaa, 0x8c, 0xcf, 0xc1, 0x37, 0xb5, 0x0b,
  0x20, 0x14, 0xbb, 0xab, 0x42, 0x04, 0xdb, 0x2f,
  0xbf, 0xcc, 0x07, 0xac, 0xf5, 0x7c, 0x96, 0xcb,
  0xc5, 0x52, 0x83, 0x6f, 0xfb, 0x7d, 0xb6, 0x74,
  0xd1, 0xa4, 0xf0, 0xf7, 0x1b, 0xf5, 0x6f, 0x35,
  0x19, 0x2a, 0x98, 0x14, 0xc8, 0x00, 0x06, 0xdc,
  0x30, 0x82, 0x06, 0xd8, 0x30, 0x82, 0x04, 0xc0,
  0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x0a, 0x61,
  0x3f, 0xb7, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x04, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
  0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
  0x30, 0x81, 0x88, 0x31, 0x0b, 0x30, 0x09, 0x06,
  0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53,
  0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04,
  0x08, 0x13, 0x0a, 0x57, 0x61, 0x73, 0x68, 0x69,
  0x6e, 0x67, 0x74, 0x6f, 0x6e, 0x31, 0x10, 0x30,
  0x0e, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x07,
  0x52, 0x65, 0x64, 0x6d, 0x6f, 0x6e, 0x64, 0x31,
  0x1e, 0x30, 0x1c, 0x06, 0x03, 0x55, 0x04, 0x0a,
  0x13, 0x15, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x73,
  0x6f, 0x66, 0x74, 0x20, 0x43, 0x6f, 0x72, 0x70,
  0x6f, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x31,
  0x32, 0x30, 0x30, 0x06, 0x03, 0x55, 0x04, 0x03,
  0x13, 0x29, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x73,
  0x6f, 0x66, 0x74, 0x20, 0x52, 0x6f, 0x6f, 0x74,
  0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69,
  0x63, 0x61, 0x74, 0x65, 0x20, 0x41, 0x75, 0x74,
  0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x20, 0x32,
  0x30, 0x31, 0x31, 0x30, 0x1e, 0x17, 0x0d, 0x31,
  0x31, 0x31, 0x30, 0x31, 0x38, 0x32, 0x32, 0x35,
  0x35, 0x31, 0x39, 0x5a, 0x17, 0x0d, 0x32, 0x36,
  0x31, 0x30, 0x31, 0x38, 0x32, 0x33, 0x30, 0x35,
  0x31, 0x39, 0x5a, 0x30, 0x7e, 0x31, 0x0b, 0x30,
  0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
  0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03,
  0x55, 0x04, 0x08, 0x13, 0x0a, 0x57, 0x61, 0x73,
  0x68, 0x69, 0x6e, 0x67, 0x74, 0x6f, 0x6e, 0x31,
  0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x07,
  0x13, 0x07, 0x52, 0x65, 0x64, 0x6d, 0x6f, 0x6e,
  0x64, 0x31, 0x1e, 0x30, 0x1c, 0x06, 0x03, 0x55,
  0x04, 0x0a, 0x13, 0x15, 0x4d, 0x69, 0x63, 0x72,
  0x6f, 0x73, 0x6f, 0x66, 0x74, 0x20, 0x43, 0x6f,
  0x72, 0x70, 0x6f, 0x72, 0x61, 0x74, 0x69, 0x6f,
  0x6e, 0x31, 0x28, 0x30, 0x26, 0x06, 0x03, 0x55,
  0x04, 0x03, 0x13, 0x1f, 0x4d, 0x69, 0x63, 0x72,
  0x6f, 0x73, 0x6f, 0x66, 0x74, 0x20, 0x53, 0x65,
  0x63, 0x75, 0x72, 0x65, 0x20, 0x53, 0x65, 0x72,
  0x76, 0x65, 0x72, 0x20, 0x43, 0x41, 0x20, 0x32,
  0x30, 0x31, 0x31, 0x30, 0x82, 0x02, 0x22, 0x30,
  0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
  0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82,
  0x02, 0x0f, 0x00, 0x30, 0x82, 0x02, 0x0a, 0x02,
  0x82, 0x02, 0x01, 0x00, 0xd0, 0x0b, 0xc0, 0xa4,
  0xa8, 0x19, 0x81, 0xe2, 0x36, 0xe5, 0xe2, 0xaa,
  0xe5, 0xf3, 0xb2, 0x15, 0x58, 0x75, 0xbe, 0xb4,
  0xe5, 0x49, 0xf1, 0xe0, 0x84, 0xf9, 0xbb, 0x0d,
  0x64, 0xef, 0x85, 0xc1, 0x81, 0x55, 0xb8, 0xf3,
  0xe7, 0xf1, 0x6d, 0x40, 0x55, 0x3d, 0xce, 0x8b,
  0x6a, 0xd1, 0x84, 0x93, 0xf5, 0x75, 0x7c, 0x5b,
  0xa4, 0xd4, 0x74, 0x10, 0xca, 0x32, 0xf3, 0x23,
  0xd3, 0xae, 0xee, 0xcf, 0x9e, 0x04, 0x58, 0xc2,
  0xd9, 0x47, 0xcb, 0xd1, 0x7c, 0x00, 0x41, 0x48,
  0x71, 0x1b, 0x01, 0x67, 0x17, 0x18, 0xaf, 0xc6,
  0xfe, 0x73, 0x03, 0x7e, 0xe4, 0xef, 0x43, 0x9c,
  0xef, 0x01, 0x71, 0x2a, 0x1f, 0x81, 0x26, 0x43,
  0x77, 0x98, 0x54, 0x57, 0x73, 0x9d, 0x55, 0x2b,
  0xf0, 0x9e, 0x8e, 0x7d, 0x06, 0x0e, 0xac, 0x1b,
  0x54, 0xf3, 0x26, 0xf7, 0xf8, 0x23, 0x08, 0x22,
  0x8b, 0x9e, 0x06, 0x1d, 0x37, 0x38, 0xfd, 0x72,
  0xd2, 0xca, 0xe5, 0x63, 0xc1, 0x9a, 0x5a, 0x7d,
  0xb2, 0x6d, 0xb3, 0x52, 0xa9, 0x6e, 0xe9, 0xae,
  0xb5, 0xfc, 0x8b, 0x36, 0xf9, 0x9e, 0xfa, 0xf6,
  0x1c, 0x58, 0x1b, 0x97, 0x56, 0xa5, 0x11, 0xe5,
  0xb7, 0x52, 0xdb, 0xbb, 0xe9, 0xf0, 0x54, 0xbf,
  0xb4, 0xff, 0x2c, 0x6c, 0xb8, 0x5d, 0x26, 0xce,
  0xa0, 0x0a, 0xd7, 0xdf, 0x93, 0xed, 0x7f, 0xdd,
  0xac, 0xf1, 0x2c, 0x73, 0x1a, 0xd9, 0x19, 0x37,
  0x55, 0xba, 0xdd, 0x22, 0x78, 0x8e, 0xa1, 0xd4,
  0x9b, 0x09, 0xf8, 0x07, 0x22, 0x31, 0x71, 0xb0,
  0x94, 0xae, 0xe0, 0xb0, 0xe7, 0x26, 0x44, 0x57,
  0x90, 0x81, 0x97, 0x15, 0xce, 0x61, 0xec, 0x65,
  0xe2, 0x4b, 0xf1, 0x85, 0x52, 0x16, 0x32, 0xf8,
  0xb5, 0x78, 0xaa, 0x7e, 0xcd, 0x4d, 0xec, 0x83,
  0x21, 0xa4, 0xa8, 0x9b, 0xbe, 0x9a, 0x6a, 0x04,
  0xe0, 0xa3, 0x1c, 0xcd, 0x56, 0x18, 0x6c, 0xfd,
  0x6b, 0x2f, 0x42, 0x3e, 0xe2, 0x37, 0xf2, 0x72,
  0xab, 0xd0, 0x78, 0x73, 0x72, 0x7b, 0xde, 0xec,
  0x00, 0x58, 0xe5, 0x21, 0x30, 0xa3, 0x08, 0x3a,
  0x99, 0xef, 0x9f, 0xc3, 0xf7, 0x7a, 0x16, 0x96,
  0x65, 0xb5, 0xc3, 0x81, 0xaf, 0xf4, 0x39, 0x70,
  0x49, 0xaf, 0xf6, 0xa9, 0xf6, 0x6a, 0x00, 0x38,
  0xf9, 0xb4, 0x08, 0x19, 0xe0, 0x1a, 0x35, 0xa5,
  0x56, 0x76, 0x22, 0x5f, 0x6a, 0xf2, 0x69, 0xae,
  0x3e, 0xad, 0x58, 0x46, 0x4d, 0xb8, 0x54, 0xf6,
  0x89, 0x41, 0x44, 0x1e, 0x72, 0xb1, 0xbc, 0x12,
  0x27, 0x53, 0xd2, 0xc1, 0xff, 0xb2, 0xcd, 0x50,
  0x98, 0x1e, 0xb5, 0xf4, 0xbb, 0xb6, 0xc2, 0x82,
  0x39, 0xd9, 0xac, 0x1b, 0xf2, 0x3b, 0x27, 0x84,
  0x6a, 0xb0, 0xc6, 0x26, 0x0b, 0xd7, 0x3a, 0x10,
  0xe7, 0xb3, 0xdb, 0x7c, 0xd3, 0x56, 0xac, 0x53,
  0x4c, 0x0b, 0xfa, 0x3b, 0x31, 0x37, 0x74, 0xd8,
  0x59, 0x2b, 0xf9, 0x00, 0x79, 0x19, 0x06, 0x7b,
  0xfd, 0x1c, 0x1d, 0x42, 0xd4, 0x41, 0x0d, 0x2f,
  0x05, 0x0e, 0xd5, 0x6b, 0x49, 0x23, 0xff, 0xcf,
  0xcd, 0xf8, 0x7a, 0x82, 0xcf, 0xda, 0x3c, 0x2d,
  0xdf, 0xe8, 0xd8, 0x12, 0x04, 0x18, 0xba, 0x1e,
  0x88, 0x77, 0xb8, 0x98, 0x1f, 0x10, 0x07, 0xbb,
  0xc8, 0x05, 0x7e, 0x0b, 0x09, 0xbf, 0x6b, 0xdd,
  0xe3, 0x4e, 0x5b, 0xb0, 0xf9, 0xc7, 0x84, 0xa6,
  0x3b, 0xca, 0x4c, 0x9f, 0x5b, 0x62, 0x29, 0xf7,
  0xc7, 0xa2, 0xa8, 0x95, 0x88, 0x70, 0x2c, 0xe5,
  0xc1, 0x3f, 0x3c, 0x52, 0x23, 0x4f, 0x40, 0x9a,
  0xc3, 0x31, 0x85, 0x83, 0x2f, 0xbf, 0x29, 0xf1,
  0x1d, 0x50, 0x8f, 0x21, 0x96, 0x07, 0xce, 0xef,
  0xf2, 0x80, 0xc2, 0x44, 0x7d, 0x9b, 0x62, 0xef,
  0x2f, 0xc3, 0x77, 0x89, 0xab, 0x45, 0x4d, 0x53,
  0x3e, 0x02, 0x79, 0xd3, 0x02, 0x03, 0x01, 0x00,
  0x01, 0xa3, 0x82, 0x01, 0x4b, 0x30, 0x82, 0x01,
  0x47, 0x30, 0x10, 0x06, 0x09, 0x2b, 0x06, 0x01,
  0x04, 0x01, 0x82, 0x37, 0x15, 0x01, 0x04, 0x03,
  0x02, 0x01, 0x00, 0x30, 0x1d, 0x06, 0x03, 0x55,
  0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x36, 0x56,
  0x89, 0x65, 0x49, 0xcb, 0x5b, 0x9b, 0x2f, 0x3c,
  0xac, 0x42, 0x16, 0x50, 0x4d, 0x91, 0xb9, 0x33,
  0xd7, 0x91, 0x30, 0x19, 0x06, 0x09, 0x2b, 0x06,
  0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x04,
  0x0c, 0x1e, 0x0a, 0x00, 0x53, 0x00, 0x75, 0x00,
  0x62, 0x00, 0x43, 0x00, 0x41, 0x30, 0x0b, 0x06,
  0x03, 0x55, 0x1d, 0x0f, 0x04, 0x04, 0x03, 0x02,
  0x01, 0x86, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d,
  0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03,
  0x01, 0x01, 0xff, 0x30, 0x1f, 0x06, 0x03, 0x55,
  0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,
  0x72, 0x2d, 0x3a, 0x02, 0x31, 0x90, 0x43, 0xb9,
  0x14, 0x05, 0x4e, 0xe1, 0xea, 0xa7, 0xc7, 0x31,
  0xd1, 0x23, 0x89, 0x34, 0x30, 0x5a, 0x06, 0x03,
  0x55, 0x1d, 0x1f, 0x04, 0x53, 0x30, 0x51, 0x30,
  0x4f, 0xa0, 0x4d, 0xa0, 0x4b, 0x86, 0x49, 0x68,
  0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63, 0x72,
  0x6c, 0x2e, 0x6d, 0x69, 0x63, 0x72, 0x6f, 0x73,
  0x6f, 0x66, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
  0x70, 0x6b, 0x69, 0x2f, 0x63, 0x72, 0x6c, 0x2f,
  0x70, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74, 0x73,
  0x2f, 0x4d, 0x69, 0x63, 0x52, 0x6f, 0x6f, 0x43,
  0x65, 0x72, 0x41, 0x75, 0x74, 0x32, 0x30, 0x31,
  0x31, 0x5f, 0x32, 0x30, 0x31, 0x31, 0x5f, 0x30,
  0x33, 0x5f, 0x32, 0x32, 0x2e, 0x63, 0x72, 0x6c,
  0x30, 0x5e, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
  0x05, 0x07, 0x01, 0x01, 0x04, 0x52, 0x30, 0x50,
  0x30, 0x4e, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
  0x05, 0x07, 0x30, 0x02, 0x86, 0x42, 0x68, 0x74,
  0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77,
  0x2e, 0x6d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f,
  0x66, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x70,
  0x6b, 0x69, 0x2f, 0x63, 0x65, 0x72, 0x74, 0x73,
  0x2f, 0x4d, 0x69, 0x63, 0x52, 0x6f, 0x6f, 0x43,
  0x65, 0x72, 0x41, 0x75, 0x74, 0x32, 0x30, 0x31,
  0x31, 0x5f, 0x32, 0x30, 0x31, 0x31, 0x5f, 0x30,
  0x33, 0x5f, 0x32, 0x32, 0x2e, 0x63, 0x72, 0x74,
  0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
  0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03,
  0x82, 0x02, 0x01, 0x00, 0x41, 0xc8, 0x61, 0xc1,
  0xf5, 0x5b, 0x9e, 0x3e, 0x91, 0x31, 0xf1, 0xb0,
  0xc6, 0xbf, 0x09, 0x01, 0xb4, 0x9d, 0xb6, 0x90,
  0x74, 0xd7, 0x09, 0xdb, 0xa6, 0x2e, 0x0d, 0x9f,
  0xc8, 0xe7, 0x76, 0x34, 0x46, 0xaf, 0x07, 0x60,
  0x89, 0x4c, 0x81, 0xb3, 0x3c, 0xd5, 0xf4, 0x12,
  0x35, 0x75, 0xc2, 0x73, 0xa5, 0xf5, 0x4d, 0x84,
  0x8c, 0xcb, 0xa4, 0x5d, 0xaf, 0xbf, 0x92, 0xf6,
  0x17, 0x08, 0x57, 0x42, 0x95, 0x72, 0x65, 0x05,
  0x76, 0x79, 0xad, 0xee, 0xd1, 0xba, 0xb8, 0x2e,
  0x54, 0xa3, 0x51, 0x07, 0xac, 0x68, 0xeb, 0x21,
  0x0c, 0xe3, 0x25, 0x81, 0xc2, 0xcd, 0x2a, 0xf2,
  0xc3, 0xff, 0xcf, 0xc2, 0xbd, 0x49, 0x18, 0x9a,
  0xc7, 0xf0, 0x84, 0xc5, 0xf9, 0x14, 0xbc, 0x6b,
  0x95, 0xe5, 0x96, 0xef, 0xb3, 0x42, 0xd2, 0x53,
  0xd5, 0x4a, 0xa0, 0x12, 0xc4, 0xae, 0x12, 0x76,
  0x53, 0x09, 0x56, 0x0e, 0x9d, 0xf7, 0xd3, 0xa6,
  0x49, 0x88, 0x50, 0xf2, 0x8a, 0x2c, 0x97, 0x20,
  0xa2, 0xbe, 0x4e, 0x78, 0xef, 0x05, 0x65, 0xb7,
  0x4b, 0xa1, 0x16, 0x88, 0xde, 0x31, 0xc7, 0x08,
  0x42, 0x24, 0x7c, 0xa4, 0x7b, 0x9e, 0x9d, 0xbc,
  0x60, 0x00, 0x5e, 0x62, 0x97, 0xe3, 0x93, 0xfc,
  0xa7, 0xfe, 0x5b, 0x7b, 0x25, 0xdf, 0xe4, 0x53,
  0x7f, 0x4b, 0xbe, 0xe6, 0x3e, 0xf0, 0xdb, 0x01,
  0x79, 0x42, 0x1c, 0x6e, 0x85, 0x6c, 0x7d, 0xb6,
  0x44, 0x30, 0xfb, 0xa5, 0x37, 0x92, 0x93, 0xb2,
  0xa5, 0xee, 0x20, 0xad, 0x3f, 0x53, 0xd5, 0xc9,
  0xf4, 0x28, 0x6b, 0x57, 0xc1, 0xf8, 0x1d, 0x6a,
  0xb7, 0x56, 0x2a, 0xb6, 0x27, 0x81, 0x1c, 0xa6,
  0x2d, 0x9f, 0xe7, 0xf4, 0xd0, 0x31, 0x83, 0x97,
  0xa8, 0x2a, 0xb6, 0xac, 0xbe, 0x1b, 0x41, 0xf5,
  0xe4, 0x89, 0x5f, 0x56, 0xfb, 0xda, 0x5a, 0xd3,
  0x5e, 0x7d, 0x55, 0x94, 0x10, 0x7e, 0x53, 0x57,
  0xf4, 0x4a, 0x3d, 0x40, 0x2a, 0xc8, 0xbd, 0x67,
  0x9f, 0x84, 0xe1, 0x10, 0xee, 0xfd, 0xda, 0x6b,
  0x15, 0x82, 0x49, 0xfc, 0x46, 0x1d, 0xff, 0x45,
  0x06, 0x74, 0x9c, 0x42, 0x14, 0xed, 0xc5, 0x39,
  0xd3, 0xb3, 0xcd, 0x0b, 0x83, 0x27, 0x90, 0x43,
  0x51, 0x92, 0xf2, 0x44, 0x82, 0xae, 0x6e, 0x9a,
  0x15, 0x17, 0xb2, 0x19, 0xfa, 0xc7, 0x45, 0x6c,
  0x98, 0x01, 0x7b, 0xbf, 0x37, 0xa9, 0xb0, 0x88,
  0xa4, 0x92, 0xbc, 0x38, 0x38, 0xe0, 0x1d, 0xe4,
  0x7c, 0x97, 0x98, 0x1a, 0x2e, 0x5f, 0xef, 0x38,
  0x65, 0xb7, 0x35, 0x2f, 0xbd, 0x7f, 0x4f, 0x21,
  0xfa, 0xc4, 0x8c, 0xd2, 0x6f, 0x06, 0xf9, 0x49,
  0x35, 0xea, 0xdf, 0x20, 0x0f, 0x25, 0xaa, 0xea,
  0x60, 0xab, 0x2c, 0x1f, 0x4b, 0x89, 0xfc, 0xb7,
  0xfa, 0x5c, 0x54, 0x90, 0x4b, 0x3e, 0xa2, 0x28,
  0x4f, 0x6c, 0xe4, 0x52, 0x65, 0xc1, 0xfd, 0x90,
  0x1c, 0x85, 0x82, 0x88, 0x6e, 0xe9, 0xa6, 0x55,
  0xdd, 0x21, 0x28, 0x79, 0x45, 0xb0, 0x14, 0xe5,
  0x0a, 0xcc, 0xe6, 0x5f, 0xc4, 0xbb, 0xdb, 0x61,
  0x34, 0x69, 0x9f, 0xac, 0x26, 0x38, 0xf7, 0xc1,
  0x29, 0x41, 0x08, 0x15, 0x2e, 0x4c, 0xa0, 0xf7,
  0xf9, 0x0c, 0x3e, 0xde, 0x5f, 0xab, 0x08, 0x09,
  0x2d, 0x83, 0xac, 0xac, 0x34, 0x83, 0x62, 0xf4,
  0xc9, 0x49, 0x42, 0x89, 0x25, 0xb5, 0x6e, 0xb2,
  0x47, 0xc5, 0xb3, 0x39, 0xa0, 0xb1, 0x20, 0x1b,
  0x2c, 0xb1, 0x8e, 0x04, 0x6f, 0xa5, 0x30, 0x49,
  0x1c, 0xd0, 0x46, 0xe9, 0x40, 0x5b, 0xf4, 0xad,
  0x6e, 0xba, 0xdb, 0x82, 0x4a, 0x87, 0x12, 0x4a,
  0x80, 0x09, 0x4d, 0xdb, 0xdf, 0x76, 0xb9, 0x05,
  0x5b, 0x1b, 0xe0, 0xbb, 0x20, 0x70, 0x5f, 0x00,
  0x25, 0xc7, 0xd3, 0x0e, 0xfa, 0x16, 0xad, 0x7b,
  0x22, 0x9e, 0x71, 0x08, 0x0c, 0x00, 0x01, 0x69,
  0x03, 0x00, 0x18, 0x61, 0x04, 0x0a, 0x05, 0x2e,
  0x5a, 0xd9, 0x4f, 0x40, 0x78, 0x4a, 0x94, 0x1d,
  0xe1, 0xbc, 0xae, 0x05, 0x96, 0x92, 0x56, 0x8d,
  0xb3, 0xe6, 0x78, 0xbd, 0xf6, 0xf4, 0xb1, 0xdf,
  0x7c, 0x43, 0x15, 0x2f, 0x77, 0x79, 0x1a, 0x06,
  0xcd, 0x25, 0x8c, 0x22, 0xe4, 0x0f, 0x4e, 0x6a,
  0x02, 0xbe, 0x3a, 0x23, 0x41, 0x49, 0x40, 0x99,
  0xb8, 0xe7, 0x5f, 0x69, 0xe2, 0x52, 0x06, 0xbd,
  0xa1, 0x0e, 0x4f, 0x8d, 0x4c, 0x00, 0xe3, 0x25,
  0x19, 0x7f, 0x3c, 0x97, 0x0b, 0xb7, 0x4a, 0x7f,
  0x3c, 0xe3, 0xd7, 0xb1, 0x67, 0x3c, 0x6f, 0x90,
  0xf4, 0xb5, 0xa0, 0x6c, 0xe8, 0x20, 0x06, 0x69,
  0xf1, 0x20, 0x4f, 0x9c, 0xae, 0x04, 0x01, 0x01,
  0x00, 0xdb, 0x46, 0xeb, 0x57, 0xfd, 0xf9, 0x8d,
  0xf4, 0x68, 0xc6, 0x9b, 0xb4, 0x2e, 0x84, 0xd3,
  0x20, 0x55, 0x71, 0xd0, 0x3c, 0x97, 0x5a, 0xdc,
  0x6f, 0xbb, 0x41, 0xd4, 0x05, 0x0d, 0xd3, 0xdc,
  0x99, 0x18, 0xb6, 0x24, 0xbb, 0x98, 0x25, 0x2b,
  0xd4, 0x8b, 0xf6, 0x19, 0x99, 0xb3, 0x30, 0x5f,
  0x62, 0xbe, 0x28, 0x34, 0xb7, 0x53, 0xbd, 0x7d,
  0x01, 0x63, 0xa2, 0xa2, 0xfa, 0xf1, 0xcc, 0xa8,
  0x9b, 0x72, 0x40, 0x32, 0x8d, 0x53, 0x78, 0x0d,
  0x7f, 0x4e, 0x06, 0x49, 0x68, 0xdb, 0x7f, 0x5f,
  0x6a, 0x21, 0xbc, 0xb4, 0x9f, 0x35, 0x84, 0x49,
  0x17, 0x30, 0x3a, 0x50, 0x08, 0x91, 0xff, 0xa6,
  0x0b, 0xb4, 0x0a, 0xe5, 0x69, 0xe1, 0x22, 0x38,
  0x19, 0xad, 0xb9, 0x2f, 0x64, 0x3a, 0x0b, 0x32,
  0x14, 0x46, 0x49, 0xc1, 0x5a, 0xd1, 0x43, 0x9c,
  0xf0, 0xfb, 0x5b, 0x1f, 0x93, 0x42, 0xcd, 0x52,
  0x56, 0x23, 0x52, 0x7f, 0x6e, 0x5a, 0x45, 0x5c,
  0x74, 0x3b, 0xbc, 0x34, 0x74, 0x8f, 0xdc, 0x36,
  0x86, 0x8c, 0xad, 0x2c, 0x49, 0xfa, 0x67, 0x21,
  0x21, 0xa8, 0xa0, 0xcd, 0x07, 0x4e, 0x2a, 0xa0,
  0x49, 0x9e, 0x45, 0xf7, 0x5d, 0xdd, 0x2b, 0x23,
  0x19, 0xc8, 0x79, 0x1d, 0x74, 0xec, 0xac, 0xdb,
  0x92, 0x5a, 0xb9, 0x4a, 0x07, 0x5f, 0xb2, 0xd9,
  0xff, 0xdf, 0x47, 0x1c, 0x6f, 0x75, 0x86, 0x01,
  0x8a, 0x9d, 0x13, 0xa8, 0x2a, 0xd9, 0x7e, 0x9d,
  0xd3, 0xe5, 0xc0, 0xb5, 0x43, 0x1e, 0xca, 0x20,
  0x7c, 0x72, 0xf2, 0xd5, 0x21, 0x17, 0xb5, 0x0a,
  0x3e, 0x41, 0xfc, 0x6d, 0x94, 0x17, 0xd8, 0xba,
  0x3c, 0xfa, 0x7b, 0xa9, 0xb1, 0xcb, 0x73, 0xb3,
  0xfb, 0xb1, 0xb9, 0xc4, 0x61, 0x5e, 0x76, 0x87,
  0xac, 0xc6, 0xef, 0x8c, 0x8e, 0x09, 0xc5, 0x67,
  0x2e, 0x47, 0x3a, 0x51, 0xdb, 0x76, 0xf4, 0x89,
  0x38, 0x0e, 0x00, 0x00, 0x00
};

    /*   {
           0x16, 0x03, 0x01, 0x00, 0xf8, 0x01, 0x00, 0x00, 0xf4, 0x03, 0x03, 0x00, 0x01,
           0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
           0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
           0x1d, 0x1e, 0x1f, 0x20, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9,
           0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
           0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x00, 0x08, 0x13, 0x02, 0x13, 0x03,
           0x13, 0x01, 0x00, 0xff, 0x01, 0x00, 0x00, 0xa3, 0x00, 0x00, 0x00, 0x18, 0x00, 0x16,
           0x00, 0x00, 0x13, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x75, 0x6c, 0x66,
           0x68, 0x65, 0x69, 0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00,
           0x01, 0x02, 0x00, 0x0a, 0x00, 0x16, 0x00, 0x14, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e,
           0x00, 0x19, 0x00, 0x18, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04,
           0x00, 0x23, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x0d,
           0x00, 0x1e, 0x00, 0x1c, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08,
           0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01,
           0x05, 0x01, 0x06, 0x01, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x2d, 0x00,
           0x02, 0x01, 0x01, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x35,
           0x80, 0x72, 0xd6, 0x36, 0x58, 0x80, 0xd1, 0xae, 0xea, 0x32, 0x9a, 0xdf, 0x91, 0x21,
           0x38, 0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e, 0x3b, 0x75, 0xe9, 0x65, 0xd0, 0xd2, 0xcd, 0x16, 0x62, 0x54};
           */

    uint16_t payload_len = sizeof(payload);

    uint16_t indx = 0;
    while (indx < payload_len)
    {

        start_parsing(payload, indx, payload_len, &indx);
    }

    return 0;
}
