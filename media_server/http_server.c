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
    s_kill,
    s_almost_dead_0,    /* Waiting for finalizers to complete. */
    s_almost_dead_1,    /* Waiting for finalizers to complete. */
    s_dead
};

typedef struct {
    http_request req;

    http_parser parser;
    size_t parsed_len;
    enum http_session_state state;
    ssize_t result;
    http_server_ctx *sx;
    
    char header_field[1024];
    char header_value[1024];
} http_request_imp;

static http_request* cast_from(http_request_imp *imp) {
    return (http_request*)imp;
}

static http_request_imp* cast_to(http_request *req) {
    return (http_request_imp*)req;
}

/*
 *         support             not support
 *  ----------------------|------------------------------|
 *  Range: bytes=0-499    | Range: bytes=0-0,-1          |
 *  Range: bytes=500-999  | Range: bytes=500-600,601-999 |
 *  Range: bytes=-500     |                              |
 *  Range: bytes=500-     |                              |
 */
static void parse_range_imp(const char *buf, size_t buf_len, int64_t *pos, int64_t *end) {
    int index, pos_start = 0, pos_end = 0, len_start = 0;
    for (index = 0; index < buf_len; ++index) {
        if (buf[index] == '=') {
            pos_start = index + 1;
        } else if (buf[index] == '-') {
            pos_end = index;
            len_start = index + 1;
        }
    }
    ASSERT(pos_start <= pos_end);
    ASSERT(pos_end < len_start);
    ASSERT(buf_len >= len_start);
    char tmp[1024] = {0};
    if (pos_start == pos_end) {
        *pos = -1;
    } else {
        strncpy(tmp, buf + pos_start, pos_end - pos_start);
        *pos = atoll(tmp);
    }

    if (len_start == buf_len) {
        *end = -1;
    } else {
        strncpy(tmp, buf + len_start, buf_len - len_start);
        tmp[buf_len - len_start] = '\0';
        *end = atoll(tmp);
    }
}

/*
// todo: manage test cases
static void check_range_parser(const char *buf, int64_t pos, int64_t end) {
    int64_t ret_pos = 0, ret_end = 0;
    parse_range_imp(buf, strlen(buf), &ret_pos, &ret_end);
    ASSERT(ret_pos == pos);
    ASSERT(ret_end == end);
}

static void range_parser_test_case() {
    YOU_LOG_DEBUG("%lld", atoll("499"));
    check_range_parser("bytes=0-499", 0, 499);
    check_range_parser("bytes=500-999", 500, 999);
    check_range_parser("bytes=-500", -1, 500);
    check_range_parser("bytes=500-", 500, -1);
}
*/

static void parse_range(http_request_imp *imp) {

    YOU_LOG_DEBUG("%s: %s", imp->header_field, imp->header_value);
    if (strcmp(imp->header_field, "Range") != 0)
        return;
    imp->req.request_range = 1;
    parse_range_imp(imp->header_value, strlen(imp->header_value), &imp->req.range_pos, &imp->req.range_end);
}


static int on_message_begin(http_parser *parser) {
    http_request_imp *imp = CONTAINER_OF(parser, http_request_imp, parser);
    imp->state = s_message_begin;
    return 0;
}

static int on_url(http_parser *parser, const char *at, size_t length) {
    http_request_imp *imp = CONTAINER_OF(parser, http_request_imp, parser);
    imp->state = s_url;
    
    http_parser_url_init(&imp->req.url);
    http_parser_parse_url(at, length, 1, &imp->req.url);
    imp->req.url_len = length;
    imp->req.url_off = at - imp->req.buf;
    return 0;
}

static int on_status(http_parser *parser, const char *at, size_t length) {
    http_request_imp *imp = CONTAINER_OF(parser, http_request_imp, parser);
    imp->state = s_status;
    return 0;
}

static int on_header_field(http_parser *parser, const char *at, size_t length) {
    http_request_imp *imp = CONTAINER_OF(parser, http_request_imp, parser);
    if (imp->state == s_header_value) {
        parse_range(imp);
        memset(imp->header_field, 0, sizeof(imp->header_field));
    }
    
    // todo: check strncat func
    strncat(imp->header_field, at, length);
    imp->state = s_header_field;
    return 0;
}

static int on_header_value(http_parser *parser, const char *at, size_t length) {
    http_request_imp *imp = CONTAINER_OF(parser, http_request_imp, parser);
    if (imp->state != s_header_value) {
        memset(imp->header_value, 0, sizeof(imp->header_value));
    }
    strncat(imp->header_value, at, length);
    imp->state = s_header_value;
    return 0;
}

static int on_headers_complete(http_parser *parser) {
    http_request_imp *imp = CONTAINER_OF(parser, http_request_imp, parser);
    parse_range(imp);
    imp->state = s_header_complete;
    return 0;
}

static int on_body(http_parser *parser, const char *at, size_t length) {
    http_request_imp *imp = CONTAINER_OF(parser, http_request_imp, parser);
    imp->state = s_body;
    
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
static enum http_session_state do_kill(http_request *req);
static enum http_session_state do_almost_dead(http_request *req);

static void on_http_handler_complete(http_request *req);

static void conn_timer_reset(http_connection *c);
static void conn_timer_expire(uv_timer_t *handle);
static void conn_read(http_connection *c);
static void conn_read_done(uv_stream_t *handle,
                           ssize_t nread,
                           const uv_buf_t *buf);
static void conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf);
static void conn_close(http_connection *c);
static void conn_close_done(uv_handle_t *handle);

static void http_request_finish_init(http_request *req, http_server_ctx *sx) {
    req->conn.rdstate = c_stop;
    req->conn.wrstate = c_stop;
    req->conn.idle_timeout = sx->idle_timeout;
    req->conn.loop = sx->loop;
    req->complete = on_http_handler_complete;
    
    http_parser_init(&cast_to(req)->parser, HTTP_REQUEST);
    cast_to(req)->state = s_message_begin;
    cast_to(req)->result = 0;
    cast_to(req)->sx = sx;
    
    CHECK(0 == uv_timer_init(sx->loop, &req->conn.timer_handle));
    conn_read(&req->conn);
    YOU_LOG_DEBUG("");
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
        case s_kill:
            new_state = do_kill(req);
            break;
        case s_almost_dead_0:
        case s_almost_dead_1:
            new_state = do_almost_dead(req);
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
        YOU_LOG_DEBUG("end");
        free(imp);
    }
}

static enum http_session_state do_http_parser(http_request *req) {
    YOU_LOG_DEBUG("");
    http_request_imp *imp = cast_to(req);
    char buf[2048] = {0};
    memcpy(buf, req->buf, imp->result);
    YOU_LOG_DEBUG("%s", buf);
    ASSERT(imp->result >= imp->parsed_len);
    imp->parsed_len += http_parser_execute(&imp->parser, &parser_setting, req->buf + imp->parsed_len, imp->result - imp->parsed_len);
    req->conn.rdstate = c_stop;
    if (imp->state != s_message_complete) {
        conn_read(&req->conn);
    }
    return imp->state;
}

static void on_http_handler_complete(http_request *req) {
    http_request_imp *imp = cast_to(req);
    imp->state = s_kill;
    do_next(req);
    
    // todo: keep alive
//    if (http_should_keep_alive(&imp->parser)) {
//        imp->state = s_message_begin;
//        req->conn.rdstate = c_stop;
//        req->conn.wrstate = c_stop;
//        conn_read(&req->conn);
//    } else {
//        imp->state = s_kill;
//        do_next(req);
//    }
}

static enum http_session_state do_handler(http_request *req) {
    http_request_imp *imp = cast_to(req);
    http_server_ctx *sx = imp->sx;
    http_server_config *config = sx->config;

    http_handler_setting *handler;
    QUEUE *q;
    QUEUE_FOREACH(q, &config->handlers) {
        handler = QUEUE_DATA(q, http_handler_setting, node);
        if (req->url.field_set & (1 << UF_PATH)) {
            size_t path_len = strlen(handler->path);
            if (path_len != req->url.field_data[UF_PATH].len) {
                continue;
            }
            if (strncmp(handler->path, req->buf + req->url_off + req->url.field_data[UF_PATH].off, path_len) == 0) {
                handler->handler(req, on_http_handler_complete);
                break;
            }
        }
    }
    
    if (q == &config->handlers) {
        config->not_found_handler(req, on_http_handler_complete);
    }

    return s_message_complete;
}

static enum http_session_state do_kill(http_request *req) {
    http_request_imp *imp = cast_to(req);
    if (imp->state >= s_almost_dead_0) {
        return imp->state;
    }
    conn_close(&req->conn);
    return s_almost_dead_0;
}

static enum http_session_state do_almost_dead(http_request *req) {
    http_request_imp *imp = cast_to(req);
    ASSERT(imp->state >= s_almost_dead_0);
    return imp->state + 1;
}

static void conn_timer_reset(http_connection *conn) {
    CHECK(0 == uv_timer_start(&conn->timer_handle,
                              conn_timer_expire,
                              conn->idle_timeout,
                              0));
}

static void conn_timer_expire(uv_timer_t *handle) {
    YOU_LOG_DEBUG("");
    ASSERT(0);
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
    // todo: test rdstate logic
    http_request *req = CONTAINER_OF(c, http_request, conn);

    cast_to(req)->result += nread;
    
    uv_read_stop(&c->handle.stream);
    uv_timer_stop(&c->timer_handle);
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

static void conn_close(http_connection *c) {
    ASSERT(c->rdstate != c_dead);
    ASSERT(c->wrstate != c_dead);
    c->rdstate = c_dead;
    c->wrstate = c_dead;
    c->timer_handle.data = c;
    c->handle.handle.data = c;
    uv_close(&c->handle.handle, conn_close_done);
    uv_close((uv_handle_t *) &c->timer_handle, conn_close_done);
}

static void conn_close_done(uv_handle_t *handle) {
    http_connection *c;
    
    c = handle->data;
    http_request *req = CONTAINER_OF(c, http_request, conn);
    do_next(req);
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
    ASSERT(cf->not_found_handler != NULL);
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