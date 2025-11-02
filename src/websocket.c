#include "websocket.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <arpa/inet.h>

#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// Base64 encode function
static char *base64_encode(const unsigned char *input, int length)
{
    BIO *bmem, *b64;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    char *buff = (char *)malloc(bptr->length + 1);
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = '\0';

    BIO_free_all(b64);

    return buff;
}

// Generate WebSocket accept key from client key
char *ws_generate_accept_key(const char *client_key)
{
    char combined[256];
    int written = snprintf(combined, sizeof(combined), "%s%s", client_key, WS_GUID);
    
    if (written < 0 || written >= (int)sizeof(combined))
    {
        return NULL;
    }

    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char *)combined, strlen(combined), hash);

    return base64_encode(hash, SHA_DIGEST_LENGTH);
}

// Handle WebSocket handshake
int ws_handle_handshake(int client_socket, const char *request, char *response, size_t response_size)
{
    (void)client_socket; // Unused in this implementation

    // Extract Sec-WebSocket-Key from request
    const char *key_header = "Sec-WebSocket-Key: ";
    char *key_start = strstr(request, key_header);
    if (!key_start)
    {
        return -1;
    }
    key_start += strlen(key_header);

    char *key_end = strstr(key_start, "\r\n");
    if (!key_end)
    {
        return -1;
    }

    char client_key[256];
    size_t key_len = key_end - key_start;
    if (key_len >= sizeof(client_key) || key_len == 0 || key_len > 1024)
    {
        return -1;
    }
    memcpy(client_key, key_start, key_len);
    client_key[key_len] = '\0';

    // Generate accept key
    char *accept_key = ws_generate_accept_key(client_key);
    if (!accept_key)
    {
        return -1;
    }

    // Create handshake response
    int written = snprintf(response, response_size,
             "HTTP/1.1 101 Switching Protocols\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Accept: %s\r\n"
             "\r\n",
             accept_key);

    free(accept_key);
    
    if (written < 0 || written >= (int)response_size)
    {
        return -1;
    }
    
    return 0;
}

// Handle WebSocket handshake for SSL connections
int ws_handle_handshake_ssl(SSL *ssl, const char *request, char *response, size_t response_size)
{
    (void)ssl; // Use the same logic, just different transport
    return ws_handle_handshake(0, request, response, response_size);
}

// Parse WebSocket frame
int ws_parse_frame(const uint8_t *data, size_t len, ws_frame_header_t *header, uint8_t **payload)
{
    // Maximum allowed WebSocket payload size (10MB)
    #define MAX_WEBSOCKET_PAYLOAD (10 * 1024 * 1024)
    
    if (len < 2)
    {
        return -1;
    }

    header->fin = (data[0] & 0x80) >> 7;
    header->opcode = data[0] & 0x0F;
    header->mask = (data[1] & 0x80) >> 7;

    size_t offset = 2;
    uint8_t payload_len = data[1] & 0x7F;

    if (payload_len == 126)
    {
        if (len < 4)
            return -1;
        header->payload_length = (data[2] << 8) | data[3];
        offset = 4;
    }
    else if (payload_len == 127)
    {
        if (len < 10)
            return -1;
        header->payload_length = 0;
        for (int i = 0; i < 8; i++)
        {
            header->payload_length = (header->payload_length << 8) | data[2 + i];
        }
        offset = 10;
    }
    else
    {
        header->payload_length = payload_len;
    }

    if (header->payload_length > MAX_WEBSOCKET_PAYLOAD)
    {
        return -1;
    }

    if (header->mask)
    {
        if (len < offset + 4)
            return -1;
        memcpy(header->masking_key, data + offset, 4);
        offset += 4;
    }

    if (len < offset + header->payload_length)
    {
        return -1;
    }

    // Unmask payload if masked
    *payload = (uint8_t *)malloc(header->payload_length);
    if (!*payload)
    {
        return -1;
    }

    if (header->mask)
    {
        for (uint64_t i = 0; i < header->payload_length; i++)
        {
            (*payload)[i] = data[offset + i] ^ header->masking_key[i % 4];
        }
    }
    else
    {
        memcpy(*payload, data + offset, header->payload_length);
    }

    return offset + header->payload_length;
}

// Create WebSocket frame
int ws_create_frame(uint8_t *buffer, size_t buffer_size, uint8_t opcode, const uint8_t *payload, size_t payload_len)
{
    size_t offset = 0;

    // First byte: FIN + opcode
    buffer[offset++] = 0x80 | (opcode & 0x0F);

    // Second byte: MASK + payload length
    if (payload_len < 126)
    {
        if (buffer_size < offset + 1 + payload_len)
            return -1;
        buffer[offset++] = payload_len;
    }
    else if (payload_len < 65536)
    {
        if (buffer_size < offset + 3 + payload_len)
            return -1;
        buffer[offset++] = 126;
        buffer[offset++] = (payload_len >> 8) & 0xFF;
        buffer[offset++] = payload_len & 0xFF;
    }
    else
    {
        if (buffer_size < offset + 9 + payload_len)
            return -1;
        buffer[offset++] = 127;
        for (int i = 7; i >= 0; i--)
        {
            buffer[offset++] = (payload_len >> (i * 8)) & 0xFF;
        }
    }

    // Copy payload
    if (payload && payload_len > 0)
    {
        memcpy(buffer + offset, payload, payload_len);
        offset += payload_len;
    }

    return offset;
}

// Send WebSocket frame
int ws_send_frame(ws_connection_t *conn, uint8_t opcode, const uint8_t *payload, size_t payload_len)
{
    // Allocate buffer with enough space for header (max 10 bytes) + payload
    size_t max_frame_size = 10 + payload_len;
    if (max_frame_size > 65536)
    {
        max_frame_size = 65536;
    }

    uint8_t buffer[65536];

    // Limit payload to avoid overflow (65536 - 10 bytes for max header)
    size_t safe_payload_len = payload_len;
    if (safe_payload_len > 65526)
    {
        safe_payload_len = 65526;
    }

    int frame_len = ws_create_frame(buffer, sizeof(buffer), opcode, payload, safe_payload_len);

    if (frame_len < 0)
    {
        return -1;
    }

    if (conn->is_ssl && conn->ssl)
    {
        return SSL_write(conn->ssl, buffer, frame_len);
    }
    else
    {
        return write(conn->socket_fd, buffer, frame_len);
    }
}

// Send text message
int ws_send_text(ws_connection_t *conn, const char *text)
{
    return ws_send_frame(conn, WS_OPCODE_TEXT, (const uint8_t *)text, strlen(text));
}

// Send pong response
int ws_send_pong(ws_connection_t *conn, const uint8_t *payload, size_t payload_len)
{
    return ws_send_frame(conn, WS_OPCODE_PONG, payload, payload_len);
}

// Close WebSocket connection
void ws_close_connection(ws_connection_t *conn, uint16_t status_code)
{
    uint8_t close_payload[2];
    close_payload[0] = (status_code >> 8) & 0xFF;
    close_payload[1] = status_code & 0xFF;

    ws_send_frame(conn, WS_OPCODE_CLOSE, close_payload, 2);

    if (conn->is_ssl && conn->ssl)
    {
        SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
    }
    close(conn->socket_fd);
}

// Validate UTF-8 encoding
bool ws_is_valid_utf8(const uint8_t *data, size_t len)
{
    size_t i = 0;
    while (i < len)
    {
        if (data[i] < 0x80)
        {
            i++;
        }
        else if ((data[i] & 0xE0) == 0xC0)
        {
            if (i + 1 >= len || (data[i + 1] & 0xC0) != 0x80)
                return false;
            i += 2;
        }
        else if ((data[i] & 0xF0) == 0xE0)
        {
            if (i + 2 >= len || (data[i + 1] & 0xC0) != 0x80 || (data[i + 2] & 0xC0) != 0x80)
                return false;
            i += 3;
        }
        else if ((data[i] & 0xF8) == 0xF0)
        {
            if (i + 3 >= len || (data[i + 1] & 0xC0) != 0x80 || (data[i + 2] & 0xC0) != 0x80 || (data[i + 3] & 0xC0) != 0x80)
                return false;
            i += 4;
        }
        else
        {
            return false;
        }
    }
    return true;
}
