#ifndef CB353AAB_2C4C_4DF9_9CE1_98F917C89149
#define CB353AAB_2C4C_4DF9_9CE1_98F917C89149
#include <stdint.h>
#include <stdbool.h>

#define MAX_len 255
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

} Record_Header;

typedef struct Handshake_Header
{

    uint16_t type;
    uint16_t length;

} Handshake_Header;

// typedef struct ClientHello
typedef struct TLS_Prameters
{

    uint16_t SNI_len;
    uint16_t common_name_len;
    char SNI[MAX_len];         //(Server Name Indication =SNI
    char common_name[MAX_len]; // Common name
    bool state;
} TLS_Prameters;


void parse_TLS(uint8_t *payload, uint16_t offset, uint16_t payload_len, Record_Header *record_header, Handshake_Header *handshake_header, TLS_Prameters *tls_prameters);
#endif /* CB353AAB_2C4C_4DF9_9CE1_98F917C89149 */
