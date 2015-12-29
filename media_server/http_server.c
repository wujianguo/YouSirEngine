//
//  http_server.c
//  YouSirCmd
//
//  Created by 吴建国 on 15/12/29.
//  Copyright © 2015年 wujianguo. All rights reserved.
//

#include <stdlib.h>
#include "http_server.h"
#include "uv.h"
#include "http_server_defs.h"

typedef struct {
    unsigned int idle_timeout;  /* Connection idle timeout in ms. */
    uv_tcp_t tcp_handle;
    uv_loop_t *loop;
    http_server_config *config;
} http_server_ctx;

typedef struct {
    uv_getaddrinfo_t getaddrinfo_req;
    http_server_config *config;
    http_server_ctx *servers;
    uv_loop_t *loop;
} http_server_state;

enum http_session_state {
    s_message_begin,
    s_url,
    s_status,
    s_header_field,
    s_header_value,
    s_header_complete,
    s_body,
    s_message_complete,
    s_dead
};

typedef struct {
    http_request req;

    http_parser parser;
    enum http_session_state state;
    ssize_t result;
    http_server_ctx *sx;
} http_request_imp;

static http_request* cast_from(http_request_imp *imp) {
    return (http_request*)imp;
}

static http_request_imp* cast_to(http_request *req) {
    return (http_request_imp*)req;
}

static int on_message_begin(http_parser *parser) {
    http_request_imp *imp = CONTAINER_OF(parser, http_request_imp, parser);
    imp->state = s_message_begin;
    return 0;
}

static int on_url(http_parser *parser, const char *at, size_t length) {
    http_request_imp *imp = CONTAINER_OF(parser, http_request_imp, parser);
    imp->state = s_url;
    char buf[1024] = {0};
    memcpy(buf, at, length);
    printf("on_url:%s\n", buf);
    
    http_parser_url_init(&imp->req.url);
    http_parser_parse_url(at, length, 1, &imp->req.url);
    imp->req.url_len = length;
    imp->req.url_off = at - imp->req.buf;
    return 0;
}

static int on_status(http_parser *parser, const char *at, size_t length) {
    http_request_imp *imp = CONTAINER_OF(parser, http_request_imp, parser);
    imp->state = s_status;
    char buf[1024] = {0};
    memcpy(buf, at, length);
    printf("on_status:%s\n", buf);
    return 0;
}

static int on_header_field(http_parser *parser, const char *at, size_t length) {
    http_request_imp *imp = CONTAINER_OF(parser, http_request_imp, parser);
    imp->state = s_header_field;
    char buf[1024] = {0};
    memcpy(buf, at, length);
    printf("on_header_field:%s\n", buf);
    return 0;
}

static int on_header_value(http_parser *parser, const char *at, size_t length) {
    http_request_imp *imp = CONTAINER_OF(parser, http_request_imp, parser);
    imp->state = s_header_value;
    char buf[1024] = {0};
    memcpy(buf, at, length);
    printf("on_header_value:%s\n", buf);
    return 0;
}

static int on_headers_complete(http_parser *parser) {
    http_request_imp *imp = CONTAINER_OF(parser, http_request_imp, parser);
    imp->state = s_header_complete;
    return 0;
}

static int on_body(http_parser *parser, const char *at, size_t length) {
    http_request_imp *imp = CONTAINER_OF(parser, http_request_imp, parser);
    imp->state = s_body;
    char buf[1024] = {0};
    memcpy(buf, at, length);
    printf("on_body:%s\n", buf);
    
    if (imp->req.body_off == 0) {
        imp->req.body_off = at - imp->req.buf;
    }
    imp->req.body_len += length;
    return 0;
}

static int on_message_complete(http_parser *parser) {
    http_request_imp *imp = CONTAINER_OF(parser, http_request_imp, parser);
    imp->state = s_message_complete;
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
    /* When on_chunk_header is called, the current chunk length is stored
     * in parser->content_length.
     */
    NULL,
    NULL
};

static void do_next(http_request *req);
static enum http_session_state do_http_parser(http_request *req);
static enum http_session_state do_handler(http_request *req);

static void conn_timer_reset(http_connection *c);
static void conn_timer_expire(uv_timer_t *handle);
static void conn_read(http_connection *c);
static void conn_read_done(uv_stream_t *handle,
                           ssize_t nread,
                           const uv_buf_t *buf);
static void conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf);


static void http_request_finish_init(http_request *req, http_server_ctx *sx) {
    req->conn.rdstate = c_stop;
    req->conn.wrstate = c_stop;
    req->conn.idle_timeout = sx->idle_timeout;
    req->conn.loop = sx->loop;
    
    http_parser_init(&cast_to(req)->parser, HTTP_REQUEST);
    cast_to(req)->state = s_message_begin;
    cast_to(req)->result = 0;
    cast_to(req)->sx = sx;
    
    CHECK(0 == uv_timer_init(sx->loop, &req->conn.timer_handle));
    conn_read(&req->conn);
}

static void do_next(http_request *req) {
    enum http_session_state new_state;
    http_request_imp *imp = cast_to(req);
    ASSERT(imp->state != s_dead);
    switch (imp->state) {
        case s_message_begin:
        case s_url:
        case s_status:
        case s_header_field:
        case s_header_value:
        case s_header_complete:
        case s_body:
            new_state = do_http_parser(req);
            break;
        case s_message_complete:
            new_state = do_handler(req);
            break;
        default:
            UNREACHABLE();
    }
    
    imp->state = new_state;
    
    if (imp->state == s_message_complete) {
        new_state = do_handler(req);
    }
    
    if (imp->state == s_dead) {
        if (DEBUG_CHECKS) {
            memset(imp, -1, sizeof(*imp));
        }
        free(imp);
    }
}

static enum http_session_state do_http_parser(http_request *req) {
    http_request_imp *imp = cast_to(req);
    http_parser_execute(&imp->parser, &parser_setting, req->buf, imp->result);
    return imp->state;
}

static void on_http_handler_complete(http_request *req) {
    
}


static enum http_session_state do_handler(http_request *req) {
    http_request_imp *imp = cast_to(req);
    http_server_ctx *sx = imp->sx;
    http_server_config *config = sx->config;

    http_handler_setting *handler;
    QUEUE *q;
    QUEUE_FOREACH(q, &config->handlers) {
        handler = QUEUE_DATA(q, http_handler_setting, node);
        if (strcmp(handler->path, "/") == 0) {
            handler->handler(req, NULL, on_http_handler_complete);
        }
    }
    
    return s_message_complete;
}


static void conn_timer_reset(http_connection *conn) {
    CHECK(0 == uv_timer_start(&conn->timer_handle,
                              conn_timer_expire,
                              conn->idle_timeout,
                              0));
}

static void conn_timer_expire(uv_timer_t *handle) {
    http_connection *c = CONTAINER_OF(handle, http_connection, timer_handle);
    http_request *req = CONTAINER_OF(c, http_request, conn);
    cast_to(req)->result = UV_ETIMEDOUT;
    do_next(req);
}

static void conn_read(http_connection *conn) {
    ASSERT(conn->rdstate == c_stop);
    CHECK(0 == uv_read_start(&conn->handle.stream, conn_alloc, conn_read_done));
    conn->rdstate = c_busy;
    conn_timer_reset(conn);
}

static void conn_read_done(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
    http_connection *c = CONTAINER_OF(handle, http_connection, handle);
    ASSERT(c->rdstate == c_busy);
    c->rdstate = c_done;
    http_request *req = CONTAINER_OF(c, http_request, conn);

    cast_to(req)->result += nread;
    
    uv_read_stop(&c->handle.stream);
    do_next(req);
}

static void conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    http_connection *c = CONTAINER_OF(handle, http_connection, handle);
    ASSERT(c->rdstate == c_busy);

    http_request *req = CONTAINER_OF(c, http_request, conn);
    http_request_imp *imp = cast_to(req);
    ASSERT(imp->result < sizeof(req->buf));
    buf->base = req->buf + imp->result;
    buf->len = sizeof(req->buf) - imp->result;
}

static void on_connection(uv_stream_t *server, int status) {
    CHECK(status == 0);

    http_server_ctx *sx = CONTAINER_OF(server, http_server_ctx, tcp_handle);
    http_request_imp *imp = malloc(sizeof(*imp));
    memset(imp, 0, sizeof(http_request_imp));
    http_request *req = cast_from(imp);
    CHECK(0 == uv_tcp_init(sx->loop, &req->conn.handle.tcp));
    CHECK(0 == uv_accept(server, &req->conn.handle.stream));
    http_request_finish_init(req, sx);
}

/* Bind a server to each address that getaddrinfo() reported. */
static void do_bind(uv_getaddrinfo_t *req, int status, struct addrinfo *addrs) {
    char addrbuf[INET6_ADDRSTRLEN + 1];
    unsigned int ipv4_naddrs;
    unsigned int ipv6_naddrs;
    http_server_state *state;
    http_server_config *cf;
    struct addrinfo *ai;
    const void *addrv;
    const char *what;
    uv_loop_t *loop;
    http_server_ctx *sx;
    unsigned int n;
    int err;
    union {
        struct sockaddr addr;
        struct sockaddr_in addr4;
        struct sockaddr_in6 addr6;
    } s;
    
    state = CONTAINER_OF(req, http_server_state, getaddrinfo_req);
    loop = state->loop;
    cf = state->config;
    
    if (status < 0) {
        YOU_LOG_ERROR("getaddrinfo(\"%s\"): %s", cf->bind_host, uv_strerror(status));
        uv_freeaddrinfo(addrs);
        return;
    }
    
    ipv4_naddrs = 0;
    ipv6_naddrs = 0;
    for (ai = addrs; ai != NULL; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET) {
            ipv4_naddrs += 1;
        } else if (ai->ai_family == AF_INET6) {
            ipv6_naddrs += 1;
        }
    }
    
    if (ipv4_naddrs == 0 && ipv6_naddrs == 0) {
        YOU_LOG_ERROR("%s has no IPv4/6 addresses", cf->bind_host);
        uv_freeaddrinfo(addrs);
        return;
    }
    
    state->servers = malloc((ipv4_naddrs + ipv6_naddrs) * sizeof(state->servers[0]));
    
    n = 0;
    for (ai = addrs; ai != NULL; ai = ai->ai_next) {
        if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6) {
            continue;
        }
        
        if (ai->ai_family == AF_INET) {
            s.addr4 = *(const struct sockaddr_in *) ai->ai_addr;
            s.addr4.sin_port = htons(cf->bind_port);
            addrv = &s.addr4.sin_addr;
        } else if (ai->ai_family == AF_INET6) {
            s.addr6 = *(const struct sockaddr_in6 *) ai->ai_addr;
            s.addr6.sin6_port = htons(cf->bind_port);
            addrv = &s.addr6.sin6_addr;
        } else {
            UNREACHABLE();
        }
        
        if (uv_inet_ntop(s.addr.sa_family, addrv, addrbuf, sizeof(addrbuf))) {
            UNREACHABLE();
        }
        
        sx = state->servers + n;
        sx->loop = loop;
        sx->idle_timeout = state->config->idle_timeout;
        sx->config = state->config;
        CHECK(0 == uv_tcp_init(loop, &sx->tcp_handle));
        
        what = "uv_tcp_bind";
        err = uv_tcp_bind(&sx->tcp_handle, &s.addr, 0);
        if (err == 0) {
            what = "uv_listen";
            err = uv_listen((uv_stream_t *) &sx->tcp_handle, 128, on_connection);
        }
        
        if (err != 0) {
            YOU_LOG_ERROR("%s(\"%s:%hu\"): %s",
                   what,
                   addrbuf,
                   cf->bind_port,
                   uv_strerror(err));
            while (n > 0) {
                n -= 1;
                uv_close((uv_handle_t *) (state->servers + n), NULL);
            }
            break;
        }
        
        YOU_LOG_INFO("listening on %s:%hu", addrbuf, cf->bind_port);
        n += 1;
    }
    
    uv_freeaddrinfo(addrs);
}


int http_server_run(const http_server_config *cf, uv_loop_t *loop) {
    struct addrinfo hints;
    http_server_state state;
    int err;
    
    memset(&state, 0, sizeof(state));
    state.servers = NULL;
    state.config = (http_server_config*)cf;
    state.loop = loop;
    
    /* Resolve the address of the interface that we should bind to.
     * The getaddrinfo callback starts the server and everything else.
     */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    
    err = uv_getaddrinfo(loop,
                         &state.getaddrinfo_req,
                         do_bind,
                         cf->bind_host,
                         NULL,
                         &hints);
    if (err != 0) {
        YOU_LOG_ERROR("getaddrinfo: %s", uv_strerror(err));
        return err;
    }
    
    /* Start the event loop.  Control continues in do_bind(). */
    if (uv_run(loop, UV_RUN_DEFAULT)) {
        abort();
    }
    
    /* Please Valgrind. */
    uv_loop_delete(loop);
    free(state.servers);
    return 0;
}