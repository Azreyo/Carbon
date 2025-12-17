#ifndef HTTP2_H
#define HTTP2_H

#include <nghttp2/nghttp2.h>
#include <openssl/ssl.h>
#include <stdbool.h>

// HTTP/2 session context
typedef struct
{
    nghttp2_session* session;
    SSL* ssl;
    int client_socket;
    bool handshake_complete;
} http2_session_t;

// HTTP/2 stream data
typedef struct
{
    int32_t stream_id;
    char request_path[256];
    char* request_method;
    int fd; // File descriptor for response
    size_t file_size;
    char* mime_type;
    char* content_length;
} http2_stream_data_t;

// Function prototypes
int http2_session_init(http2_session_t* session, int client_socket, SSL* ssl);
void http2_session_cleanup(http2_session_t* session);
int http2_handle_connection(http2_session_t* session);
int http2_send_response(http2_session_t* session, int32_t stream_id,
                        const char* data, size_t len, bool end_stream);
int http2_send_error(http2_session_t* session, int32_t stream_id,
                     int status_code, const char* message);

// ALPN callback for protocol selection
int alpn_select_proto_cb(SSL* ssl, const unsigned char** out,
                         unsigned char* outlen, const unsigned char* in,
                         unsigned int inlen, void* arg);

#endif