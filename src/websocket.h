#ifndef WEBSOCKET_H
#define WEBSOCKET_H

#include <stdint.h>
#include <stdbool.h>
#include <openssl/ssl.h>

// WebSocket opcodes
#define WS_OPCODE_CONTINUATION 0x0
#define WS_OPCODE_TEXT 0x1
#define WS_OPCODE_BINARY 0x2
#define WS_OPCODE_CLOSE 0x8
#define WS_OPCODE_PING 0x9
#define WS_OPCODE_PONG 0xA

// WebSocket frame header structure
typedef struct
{
    uint8_t fin;
    uint8_t opcode;
    uint8_t mask;
    uint64_t payload_length;
    uint8_t masking_key[4];
} ws_frame_header_t;

// WebSocket connection context
typedef struct
{
    int socket_fd;
    SSL* ssl;
    bool is_ssl;
    bool handshake_complete;
} ws_connection_t;

// Function prototypes
int ws_handle_handshake(int client_socket, const char* request, char* response, size_t response_size);
int ws_handle_handshake_ssl(SSL* ssl, const char* request, char* response, size_t response_size);
int ws_parse_frame(const uint8_t* data, size_t len, ws_frame_header_t* header, uint8_t** payload);
int ws_create_frame(uint8_t* buffer, size_t buffer_size, uint8_t opcode, const uint8_t* payload, size_t payload_len);
int ws_send_frame(ws_connection_t* conn, uint8_t opcode, const uint8_t* payload, size_t payload_len);
int ws_send_text(ws_connection_t* conn, const char* text);
int ws_send_pong(ws_connection_t* conn, const uint8_t* payload, size_t payload_len);
void ws_close_connection(ws_connection_t* conn, uint16_t status_code);

// Helper functions
char* ws_generate_accept_key(const char* client_key);
bool ws_is_valid_utf8(const uint8_t* data, size_t len);

#endif
