#include "http2.h"
#include "server_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

extern ServerConfig config;

extern char* get_mime_type(const char* filepath);
extern char* sanitize_url(const char* url);

// ALPN callback - select HTTP/2 protocol
int alpn_select_proto_cb(SSL* ssl, const unsigned char** out,
                         unsigned char* outlen, const unsigned char* in,
                         unsigned int inlen, void* arg)
{
    (void)ssl;
    (void)arg;

    int ret = nghttp2_select_next_protocol((unsigned char**)out, outlen,
                                           in, inlen);

    if (ret == 1)
        return SSL_TLSEXT_ERR_OK; // HTTP/2 selected
    else if (ret == 0)
        return SSL_TLSEXT_ERR_OK; // HTTP/1.1 selected

    return SSL_TLSEXT_ERR_OK;
}

// Data read callback for nghttp2
static ssize_t file_read_callback(nghttp2_session* session, int32_t stream_id,
                                  uint8_t* buf, size_t length,
                                  uint32_t* data_flags,
                                  nghttp2_data_source* source,
                                  void* user_data)
{
    (void)session;
    (void)stream_id;
    (void)user_data;

    int fd = source->fd;
    ssize_t nread;

    while ((nread = read(fd, buf, length)) == -1 && errno == EINTR);

    if (nread == -1)
    {
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }

    if (nread == 0)
    {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }

    return nread;
}

// Send callback for nghttp2
static ssize_t send_callback(nghttp2_session* session, const uint8_t* data,
                             size_t length, int flags, void* user_data)
{
    (void)session;
    (void)flags;

    http2_session_t* h2_session = (http2_session_t*)user_data;
    ssize_t rv;

    if (h2_session->ssl)
    {
        rv = SSL_write(h2_session->ssl, data, (int)length);
        if (rv < 0)
        {
            int ssl_error = SSL_get_error(h2_session->ssl, rv);
            if (ssl_error == SSL_ERROR_WANT_WRITE)
            {
                return NGHTTP2_ERR_WOULDBLOCK;
            }
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    }
    else
    {
        rv = write(h2_session->client_socket, data, length);
        if (rv < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                return NGHTTP2_ERR_WOULDBLOCK;
            }
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    }

    return rv;
}

// Receive callback for nghttp2
static ssize_t recv_callback(nghttp2_session* session, uint8_t* buf,
                             size_t length, int flags, void* user_data)
{
    (void)session;
    (void)flags;

    http2_session_t* h2_session = (http2_session_t*)user_data;
    ssize_t rv;

    if (h2_session->ssl)
    {
        rv = SSL_read(h2_session->ssl, buf, (int)length);
        if (rv < 0)
        {
            int ssl_error = SSL_get_error(h2_session->ssl, rv);
            if (ssl_error == SSL_ERROR_WANT_READ)
            {
                return NGHTTP2_ERR_WOULDBLOCK;
            }
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        if (rv == 0)
        {
            return NGHTTP2_ERR_EOF;
        }
    }
    else
    {
        rv = read(h2_session->client_socket, buf, length);
        if (rv < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                return NGHTTP2_ERR_WOULDBLOCK;
            }
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        if (rv == 0)
        {
            return NGHTTP2_ERR_EOF;
        }
    }

    return rv;
}

// Frame receive callback
static int on_frame_recv_callback(nghttp2_session* session,
                                  const nghttp2_frame* frame,
                                  void* user_data)
{
    (void)user_data;

    switch (frame->hd.type)
    {
    case NGHTTP2_HEADERS:
        if (frame->headers.cat == NGHTTP2_HCAT_REQUEST)
        {
            log_event("HTTP/2: Received HEADERS frame (request)");

            // Get stream data
            http2_stream_data_t* stream_data =
                (http2_stream_data_t*)nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);

            if (stream_data && (frame->hd.flags & NGHTTP2_FLAG_END_STREAM))
            {
                // Request is complete, send response
                char* path = stream_data->request_path;
                if (strlen(path) == 0)
                {
                    strcpy(path, "/");
                }

                // Sanitize URL
                char* sanitized = sanitize_url(path);
                if (!sanitized)
                {
                    log_event("HTTP/2: Blocked malicious URL");

                    // Send 403 error
                    nghttp2_nv hdrs[] = {
                        {(uint8_t*)":status", (uint8_t*)"403", 7, 3, NGHTTP2_NV_FLAG_NONE},
                        {(uint8_t*)"content-type", (uint8_t*)"text/plain", 12, 10, NGHTTP2_NV_FLAG_NONE}
                    };
                    nghttp2_submit_response(session, frame->hd.stream_id, hdrs, 2, NULL);
                    break;
                }

                // Build file path
                char filepath[512];
                snprintf(filepath, sizeof(filepath), "www%s",
                         (strcmp(sanitized, "/") == 0) ? "/index.html" : sanitized);
                free(sanitized);

                // Open file
                int fd = open(filepath, O_RDONLY);
                if (fd == -1)
                {
                    log_event("HTTP/2: File not found");

                    // Send 404 error
                    nghttp2_nv hdrs[] = {
                        {(uint8_t*)":status", (uint8_t*)"404", 7, 3, NGHTTP2_NV_FLAG_NONE},
                        {(uint8_t*)"content-type", (uint8_t*)"text/plain", 12, 10, NGHTTP2_NV_FLAG_NONE}
                    };
                    nghttp2_submit_response(session, frame->hd.stream_id, hdrs, 2, NULL);
                    break;
                }

                // Get file size
                struct stat st;
                if (fstat(fd, &st) == -1)
                {
                    close(fd);
                    log_event("HTTP/2: Error getting file size");

                    // Send 500 error
                    nghttp2_nv hdrs[] = {
                        {(uint8_t*)":status", (uint8_t*)"500", 7, 3, NGHTTP2_NV_FLAG_NONE},
                        {(uint8_t*)"content-type", (uint8_t*)"text/plain", 12, 10, NGHTTP2_NV_FLAG_NONE}
                    };
                    nghttp2_submit_response(session, frame->hd.stream_id, hdrs, 2, NULL);
                    break;
                }

                if (st.st_size < 0 || st.st_size > 0x7FFFFFFFFFFFFFFF)
                {
                    close(fd);
                    log_event("HTTP/2: File size out of bounds");

                    // Send 500 error
                    nghttp2_nv hdrs[] = {
                        {(uint8_t*)":status", (uint8_t*)"500", 7, 3, NGHTTP2_NV_FLAG_NONE},
                        {(uint8_t*)"content-type", (uint8_t*)"text/plain", 12, 10, NGHTTP2_NV_FLAG_NONE}
                    };
                    nghttp2_submit_response(session, frame->hd.stream_id, hdrs, 2, NULL);
                    break;
                }

                // Get MIME type
                char* mime_type = get_mime_type(filepath);
                if (!mime_type)
                {
                    mime_type = strdup("application/octet-stream");
                }

                // Store file info in stream data
                stream_data->fd = fd;
                stream_data->file_size = st.st_size;
                stream_data->mime_type = mime_type;

                // Build response headers - allocate content length string
                char* content_length = malloc(32);
                if (!content_length)
                {
                    close(fd);
                    free(mime_type);
                    log_event("HTTP/2: Memory allocation failed");
                    break;
                }
                snprintf(content_length, 32, "%ld", (long)st.st_size);

                // Store content_length in stream_data for cleanup
                stream_data->content_length = content_length;

                nghttp2_nv hdrs[] = {
                    {(uint8_t*)":status", (uint8_t*)"200", 7, 3, NGHTTP2_NV_FLAG_NONE},
                    {(uint8_t*)"content-type", (uint8_t*)mime_type, 12, strlen(mime_type), NGHTTP2_NV_FLAG_NONE},
                    {
                        (uint8_t*)"content-length", (uint8_t*)content_length, 14, strlen(content_length),
                        NGHTTP2_NV_FLAG_NONE
                    },
                    {(uint8_t*)"server", (uint8_t*)"Carbon/2.0", 6, 10, NGHTTP2_NV_FLAG_NONE}
                };

                // Submit response with file data provider
                nghttp2_data_provider data_prd;
                data_prd.source.fd = fd;
                data_prd.read_callback = file_read_callback;

                nghttp2_submit_response(session, frame->hd.stream_id, hdrs, 4, &data_prd);

                char log_msg[1024];
                snprintf(log_msg, sizeof(log_msg), "HTTP/2: Response submitted for %s (%ld bytes)",
                         filepath, (long)st.st_size);
                log_event(log_msg);
            }
        }
        break;
    case NGHTTP2_DATA:
        log_event("HTTP/2: Received DATA frame");
        break;
    case NGHTTP2_SETTINGS:
        log_event("HTTP/2: Received SETTINGS frame");
        break;
    default:
        break;
    }

    return 0;
}

// Stream close callback
static int on_stream_close_callback(nghttp2_session* session, int32_t stream_id,
                                    uint32_t error_code, void* user_data)
{
    (void)error_code;
    (void)user_data;

    // Get stream data and clean up
    http2_stream_data_t* stream_data =
        (http2_stream_data_t*)nghttp2_session_get_stream_user_data(session, stream_id);

    if (stream_data)
    {
        if (stream_data->fd != -1)
        {
            close(stream_data->fd);
        }
        if (stream_data->mime_type)
        {
            free(stream_data->mime_type);
        }
        if (stream_data->content_length)
        {
            free(stream_data->content_length);
        }
        free(stream_data);
    }

    log_event("HTTP/2: Stream closed");

    return 0;
}

// Header callback
static int on_header_callback(nghttp2_session* session,
                              const nghttp2_frame* frame,
                              const uint8_t* name, size_t namelen,
                              const uint8_t* value, size_t valuelen,
                              uint8_t flags, void* user_data)
{
    (void)flags;
    (void)user_data;

    if (frame->hd.type != NGHTTP2_HEADERS ||
        frame->headers.cat != NGHTTP2_HCAT_REQUEST)
    {
        return 0;
    }

    // Get stream data
    http2_stream_data_t* stream_data =
        (http2_stream_data_t*)nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);

    if (!stream_data)
    {
        return 0;
    }

    // Process request headers
    if (namelen == 5 && memcmp(name, ":path", 5) == 0)
    {
        size_t copy_len = valuelen < sizeof(stream_data->request_path) - 1
                              ? valuelen
                              : sizeof(stream_data->request_path) - 1;
        memcpy(stream_data->request_path, value, copy_len);
        stream_data->request_path[copy_len] = '\0';

        char log_msg[512];
        snprintf(log_msg, sizeof(log_msg), "HTTP/2: Request path: %s", stream_data->request_path);
        log_event(log_msg);
    }

    return 0;
}

// Begin headers callback
static int on_begin_headers_callback(nghttp2_session* session,
                                     const nghttp2_frame* frame,
                                     void* user_data)
{
    (void)session;
    (void)user_data;

    if (frame->hd.type != NGHTTP2_HEADERS ||
        frame->headers.cat != NGHTTP2_HCAT_REQUEST)
    {
        return 0;
    }

    // Allocate stream data
    http2_stream_data_t* stream_data = calloc(1, sizeof(http2_stream_data_t));
    if (!stream_data)
    {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    stream_data->stream_id = frame->hd.stream_id;
    stream_data->fd = -1;

    nghttp2_session_set_stream_user_data(session, frame->hd.stream_id, stream_data);
    free(stream_data);
    return 0;
}

// Data chunk receive callback
static int on_data_chunk_recv_callback(nghttp2_session* session, uint8_t flags,
                                       int32_t stream_id, const uint8_t* data,
                                       size_t len, void* user_data)
{
    (void)session;
    (void)flags;
    (void)stream_id;
    (void)data;
    (void)len;
    (void)user_data;

    // Handle POST data if needed
    return 0;
}

// Initialize HTTP/2 session
int http2_session_init(http2_session_t* h2_session, int client_socket, SSL* ssl)
{
    h2_session->client_socket = client_socket;
    h2_session->ssl = ssl;
    h2_session->handshake_complete = false;

    // Setup callbacks
    nghttp2_session_callbacks* callbacks;
    nghttp2_session_callbacks_new(&callbacks);

    nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
    nghttp2_session_callbacks_set_recv_callback(callbacks, recv_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header_callback);
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, on_begin_headers_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);

    // Create server session
    int rv = nghttp2_session_server_new(&h2_session->session, callbacks, h2_session);
    nghttp2_session_callbacks_del(callbacks);

    if (rv != 0)
    {
        log_event("HTTP/2: Failed to create session");
        return -1;
    }

    // Send initial SETTINGS frame
    nghttp2_settings_entry settings[] = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100},
        {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 65535}
    };

    rv = nghttp2_submit_settings(h2_session->session, NGHTTP2_FLAG_NONE,
                                 settings, sizeof(settings) / sizeof(settings[0]));
    if (rv != 0)
    {
        log_event("HTTP/2: Failed to submit settings");
        nghttp2_session_del(h2_session->session);
        return -1;
    }

    h2_session->handshake_complete = true;
    log_event("HTTP/2: Session initialized");

    return 0;
}

// Cleanup HTTP/2 session
void http2_session_cleanup(http2_session_t* h2_session)
{
    if (h2_session->session)
    {
        nghttp2_session_del(h2_session->session);
        h2_session->session = NULL;
    }
}

// Send HTTP/2 response
int http2_send_response(http2_session_t* h2_session, int32_t stream_id,
                        const char* data, size_t len, bool end_stream)
{
    (void)data; // Unused in current implementation
    (void)len; // Unused in current implementation
    (void)end_stream; // Unused in current implementation

    // Send response headers
    nghttp2_nv hdrs[] = {
        {(uint8_t*)":status", (uint8_t*)"200", 7, 3, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t*)"content-type", (uint8_t*)"text/html", 12, 9, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t*)"server", (uint8_t*)"Carbon/2.0", 6, 10, NGHTTP2_NV_FLAG_NONE}
    };

    int rv = nghttp2_submit_response(h2_session->session, stream_id, hdrs, 3, NULL);
    if (rv != 0)
    {
        return -1;
    }

    return nghttp2_session_send(h2_session->session);
}

// Send HTTP/2 error response
int http2_send_error(http2_session_t* h2_session, int32_t stream_id,
                     int status_code, const char* message)
{
    char status_str[4];
    snprintf(status_str, sizeof(status_str), "%d", status_code);

    nghttp2_nv hdrs[] = {
        {(uint8_t*)":status", (uint8_t*)status_str, 7, strlen(status_str), NGHTTP2_NV_FLAG_NONE},
        {(uint8_t*)"content-type", (uint8_t*)"text/plain", 12, 10, NGHTTP2_NV_FLAG_NONE}
    };

    int rv = nghttp2_submit_response(h2_session->session, stream_id, hdrs, 2, NULL);
    if (rv != 0)
    {
        return -1;
    }

    if (message)
    {
        nghttp2_data_provider prd;
        prd.source.ptr = (void*)message;
        prd.read_callback = NULL;

        nghttp2_submit_data(h2_session->session, NGHTTP2_FLAG_END_STREAM,
                            stream_id, &prd);
    }

    return nghttp2_session_send(h2_session->session);
}

// Handle HTTP/2 connection
int http2_handle_connection(http2_session_t* h2_session)
{
    // Receive and process frames first
    int rv = nghttp2_session_recv(h2_session->session);
    if (rv != 0)
    {
        if (rv == NGHTTP2_ERR_EOF)
        {
            log_event("HTTP/2: Connection closed");
            return 0;
        }
        char err_msg[128];
        snprintf(err_msg, sizeof(err_msg), "HTTP/2: Session receive failed: %s", nghttp2_strerror(rv));
        log_event(err_msg);
        return -1;
    }

    // Send all pending data
    rv = nghttp2_session_send(h2_session->session);
    if (rv != 0)
    {
        char err_msg[128];
        snprintf(err_msg, sizeof(err_msg), "HTTP/2: Session send failed: %s", nghttp2_strerror(rv));
        log_event(err_msg);
        return -1;
    }

    // Check if session wants to terminate
    if (nghttp2_session_want_read(h2_session->session) == 0 &&
        nghttp2_session_want_write(h2_session->session) == 0)
    {
        log_event("HTTP/2: Session terminated normally");
        return 0;
    }

    return 1;
}