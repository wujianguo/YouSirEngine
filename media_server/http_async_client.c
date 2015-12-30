//
//  http_async_client.c
//  YouSirCmd
//
//  Created by 吴建国 on 15/12/30.
//  Copyright © 2015年 wujianguo. All rights reserved.
//

#include "http_async_client.h"
#include <stdlib.h>

// todo: check status in callback

enum http_async_client_state {
    s_idle,
    s_connecting,
    s_connected,
    s_sending,
    s_receiving,
    s_closing,
    s_dead
};

typedef struct http_async_client {
    http_connection conn;
    struct http_async_client_settings settings;
    
    enum http_async_client_state state;
    char host[MAX_HOST_LEN + 1];
    unsigned short port;
    http_parser parser;
    
    union {
        uv_getaddrinfo_t addrinfo_req;
        uv_connect_t connect_req;
        uv_req_t req;
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
        char buf[2048];  /* Scratch space. Used to read data into. */
    } t;
    
    char *recv_buf;
    char *send_buf;
    
    int callbacking;
    int destroy;
    
    void *user_data;
} http_async_client;


static int on_message_begin(http_parser *parser) {
    http_async_client *client = CONTAINER_OF(parser, http_async_client, parser);
    if (client->settings.on_message_begin) {
        return client->settings.on_message_begin(client, client->user_data);
    }
    return 0;
}

static int on_url(http_parser *parser, const char *at, size_t length) {
    http_async_client *client = CONTAINER_OF(parser, http_async_client, parser);
    if (client->settings.on_url) {
        return client->settings.on_url(client, at, length, client->user_data);
    }
    return 0;
}

static int on_status(http_parser *parser, const char *at, size_t length) {
    http_async_client *client = CONTAINER_OF(parser, http_async_client, parser);
    if (client->settings.on_status) {
        return client->settings.on_status(client, at, length, client->user_data);
    }
    return 0;
}

static int on_header_field(http_parser *parser, const char *at, size_t length) {
    http_async_client *client = CONTAINER_OF(parser, http_async_client, parser);
    if (client->settings.on_header_field) {
        return client->settings.on_header_field(client, at, length, client->user_data);
    }
    return 0;
}

static int on_header_value(http_parser *parser, const char *at, size_t length) {
    http_async_client *client = CONTAINER_OF(parser, http_async_client, parser);
    if (client->settings.on_header_value) {
        return client->settings.on_header_value(client, at, length, client->user_data);
    }
    return 0;
}

static int on_headers_complete(http_parser *parser) {
    http_async_client *client = CONTAINER_OF(parser, http_async_client, parser);
    if (client->settings.on_headers_complete) {
        return client->settings.on_headers_complete(client, client->user_data);
    }
    return 0;
}

static int on_body(http_parser *parser, const char *at, size_t length) {
    http_async_client *client = CONTAINER_OF(parser, http_async_client, parser);
    if (client->settings.on_body) {
        return client->settings.on_body(client, at, length, client->user_data);
    }
    return 0;
}

static int on_message_complete(http_parser *parser) {
    http_async_client *client = CONTAINER_OF(parser, http_async_client, parser);
    if (client->settings.on_message_complete) {
        return client->settings.on_message_complete(client, client->user_data);
    }
    return 0;
}

static int on_chunk_header(http_parser *parser) {
    http_async_client *client = CONTAINER_OF(parser, http_async_client, parser);
    if (client->settings.on_chunk_header) {
        return client->settings.on_chunk_header(client, client->user_data);
    }
    return 0;
}

static int on_chunk_complete(http_parser *parser) {
    http_async_client *client = CONTAINER_OF(parser, http_async_client, parser);
    if (client->settings.on_chunk_complete) {
        return client->settings.on_chunk_complete(client, client->user_data);
    }
    return 0;
}

static struct http_parser_settings parser_setting = {
    on_message_begin,
    on_url,
    on_status,
    on_header_field,
    on_header_value,
    on_headers_complete,
    on_body,
    on_message_complete,
    on_chunk_header,
    on_chunk_complete
};

void on_close(uv_handle_t* handle) {
    http_connection *conn = CONTAINER_OF(handle, http_connection, handle);
    http_async_client *client = CONTAINER_OF(conn, http_async_client, conn);
    if (client->recv_buf) {
        free(client->recv_buf);
    }
    if (client->send_buf) {
        free(client->send_buf);
    }
    YOU_LOG_DEBUG("");
    free(client);
}

static void on_read_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    YOU_LOG_DEBUG("");
    http_connection *conn = CONTAINER_OF(handle, http_connection, handle);
    http_async_client *client = CONTAINER_OF(conn, http_async_client, conn);
    ASSERT(client->state == s_receiving);
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
    client->recv_buf = buf->base;
}

static void on_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    YOU_LOG_DEBUG("");
    http_connection *conn = CONTAINER_OF(stream, http_connection, handle.stream);
    http_async_client *client = CONTAINER_OF(conn, http_async_client, conn);
    ASSERT(client->state == s_receiving);
    client->callbacking = 1;
    http_parser_execute(&client->parser, &parser_setting, buf->base, nread);
    client->callbacking = 0;
    free(client->recv_buf);
    client->recv_buf = NULL;
    if (client->destroy) {
        http_async_client_uninit(client);
    }
}

static void on_write_done(uv_write_t *req, int status) {
    YOU_LOG_DEBUG("");
    ASSERT(status==0);
    http_connection *conn = CONTAINER_OF(req, http_connection, write_req);
    http_async_client *client = CONTAINER_OF(conn, http_async_client, conn);
    ASSERT(client->state == s_sending);
    free(client->send_buf);
    client->send_buf = NULL;
    client->state = s_receiving;
    uv_read_start(&conn->handle.stream, on_read_alloc, on_read);
}

static void on_connect(uv_connect_t* req, int status) {
    YOU_LOG_DEBUG("");
    ASSERT(status==0);
    http_async_client *client = CONTAINER_OF(req, http_async_client, t.connect_req);
    ASSERT(client->state == s_connecting);
    client->state = s_connected;
    if (client->settings.on_connect) {
        client->settings.on_connect(client, client->user_data);
    }
}

static void on_get_addrinfo(uv_getaddrinfo_t *req, int status, struct addrinfo *addrs) {
    http_async_client *client = CONTAINER_OF(req, http_async_client, t.addrinfo_req);
    ASSERT(client->state == s_connecting);
    ASSERT(status == 0); // todo: check status
    if (status == 0) {
        /* todo: FIXME(bnoordhuis) Should try all addresses. */
        if (addrs->ai_family == AF_INET) {
            client->t.addr4 = *(const struct sockaddr_in *) addrs->ai_addr;
        } else if (addrs->ai_family == AF_INET6) {
            client->t.addr6 = *(const struct sockaddr_in6 *) addrs->ai_addr;
        } else {
            UNREACHABLE();
        }
    }
    
    uv_freeaddrinfo(addrs);
    
    uv_tcp_init(client->conn.loop, &client->conn.handle.tcp);
    uv_tcp_connect(&client->t.connect_req, &client->conn.handle.tcp, &client->t.addr, on_connect);
}

http_async_client* http_async_client_init(uv_loop_t *loop, struct http_async_client_settings settings, void *data) {
    http_async_client *client = (http_async_client*)malloc(sizeof(http_async_client));
    memset(client, 0, sizeof(http_async_client));
    client->user_data = data;
    client->state = s_idle;
    client->settings = settings;
    http_parser_init(&client->parser, HTTP_RESPONSE);
    
    client->conn.loop = loop;

    CHECK(0 == uv_timer_init(loop, &client->conn.timer_handle));
    return client;
}

int http_async_client_connect(http_async_client *client, const char host[MAX_HOST_LEN], unsigned short port) {
    strncpy(client->host, host, MAX_HOST_LEN);
    client->port = port;
    client->state = s_connecting;
    
    struct addrinfo hints;
    int err;

    /* Resolve the address of the interface that we should bind to.
     * The getaddrinfo callback starts the server and everything else.
     */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    
    char port_str[16] = {0};
    snprintf(port_str, 16, "%u", port);
    err = uv_getaddrinfo(client->conn.loop, &client->t.addrinfo_req, on_get_addrinfo, host, port_str, &hints);
    return err;
}

int http_async_client_send(http_async_client *client, const char *buf, size_t len) {
    ASSERT(client->send_buf == NULL && (client->state == s_receiving || client->state == s_connected));
    client->state = s_sending;
    client->send_buf = (char*)malloc(len);
    memcpy(client->send_buf, buf, len);
    uv_buf_t b;
    b.base = client->send_buf;
    b.len = len;
    uv_write(&client->conn.write_req, &client->conn.handle.stream, &b, 1, on_write_done);
    return 0;
}

void http_async_client_uninit(http_async_client *client) {
    if (client->callbacking) {
        client->destroy = 1;
        return;
    }
    ASSERT(client->state == s_receiving);
    client->state = s_closing;
    uv_close(&client->conn.handle.handle, on_close);
}

