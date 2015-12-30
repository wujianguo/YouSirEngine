//
//  main.c
//  YouSirCmd
//
//  Created by wujianguo on 15/12/28.
//  Copyright © 2015年 wujianguo. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include "uv.h"
#include "http_server_defs.h"
#include "http_server.h"
#include "http_async_client.h"

#define DEFAULT_BIND_HOST     "127.0.0.1"
#define DEFAULT_BIND_PORT     9013
#define DEFAULT_IDLE_TIMEOUT  (5 * 1000)


#include "tree.h"
#include "queue.h"


static void conn_write(http_connection *c, const void *data, unsigned int len);
static void conn_write_done(uv_write_t *req, int status);

static void root_handler(http_request *req, http_session_complete_cb complete) {
    YOU_LOG_DEBUG("%s", req->buf);
    char url[1024] = {0};
    memcpy(url, req->buf + req->url_off, req->url_len);
    YOU_LOG_DEBUG("url:%s", url);
    
    char body[1024] = {0};
    memcpy(body, req->buf + req->body_off, req->body_len);
    YOU_LOG_DEBUG("body:%s", body);
}

static void meta_handler(http_request *req, http_session_complete_cb complete) {
    YOU_LOG_DEBUG("");    
}

static void not_found_handler(http_request *req, http_session_complete_cb complete) {
    YOU_LOG_DEBUG("");
    req->data = malloc(1024);
    memset(req->data, 0, 1024);
    
    const char format[] = "HTTP/1.1 404 Not Found\r\n"
        "Server: YouSir/2\r\n"
        "Content-type: text/plain\r\n"
        "Content-Length: %lu\r\n"
        "\r\n"
        "%s";
    
    const char body[] = "not found\n";
    snprintf(req->data, 1024, format, strlen(body), body);
    
    conn_write(&req->conn, req->data, (unsigned int)strlen(req->data));
}

static void conn_write(http_connection *c, const void *data, unsigned int len) {
    uv_buf_t buf;
    
    ASSERT(c->wrstate == c_stop || c->wrstate == c_done);
    c->wrstate = c_busy;
    
    /* It's okay to cast away constness here, uv_write() won't modify the
     * memory.
     */
    buf.base = (char *) data;
    buf.len = len;
    
    CHECK(0 == uv_write(&c->write_req,
                        &c->handle.stream,
                        &buf,
                        1,
                        conn_write_done));
}

static void conn_write_done(uv_write_t *req, int status) {
    http_connection *c;
    
    if (status == UV_ECANCELED) {
        return;  /* Handle has been closed. */
    }
    
    c = CONTAINER_OF(req, http_connection, write_req);
    ASSERT(c->wrstate == c_busy);
    c->wrstate = c_done;

    http_request *r = CONTAINER_OF(c, http_request, conn);
    free(r->data);
    r->complete(r);
}

#define HTTP_SERVER_ADD_HANDLER(queue, custom_path, custom_handler)     \
    do {                                                                \
        http_handler_setting setting = {0};                             \
        strncpy(setting.path, custom_path, sizeof(setting.path));       \
        setting.handler = custom_handler;                               \
        QUEUE_INIT(&setting.node);                                      \
        QUEUE_INSERT_TAIL(queue, &setting.node);                        \
    }                                                                   \
    while(0)



uv_timer_t timer_handle;

static void on_timer_expire2(uv_timer_t *handle) {
    YOU_LOG_DEBUG("");
    http_async_client *client = (http_async_client*)handle->data;
    const char format[] =     "ache\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
    "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.106 Safari/537.36\r\n"
    "Accept-Encoding: gzip, deflate\r\n"
    "Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.6,en;q=0.4\r\n"
    "\r\n";

    http_async_client_send(client, format, strlen(format));
}


static int on_connect(http_async_client* client, void *data) {
    YOU_LOG_DEBUG("");
    const char format[] = "GET /1.json HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    "Connection: keep-alive\r\n"
    "Cache-Control: no-c";
    
    http_async_client_send(client, format, strlen(format));
    
    timer_handle.data = client;
    uv_timer_start(&timer_handle, on_timer_expire2, 1000, 0);
    return 0;
}


static int on_connect2(http_async_client* client, void *data) {
    YOU_LOG_DEBUG("");
    const char format[] = "GET /1.json HTTP/1.1\r\n"
        "Host: www.puacg.com\r\n"
        "Connection: keep-alive\r\n"
        "Cache-Control: no-cache\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
        "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.106 Safari/537.36\r\n"
        "Accept-Encoding: gzip, deflate\r\n"
        "Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.6,en;q=0.4\r\n"
        "\r\n";

    http_async_client_send(client, format, strlen(format));
    
    timer_handle.data = client;
    uv_timer_start(&timer_handle, on_timer_expire2, 500, 0);
    return 0;
}

static int on_message_begin(http_async_client* client, void *data) {
    YOU_LOG_DEBUG("");
    return 0;
}

static int on_url(http_async_client* client, const char *at, size_t length, void *data) {
    return 0;
}

static int on_status(http_async_client* client, const char *at, size_t length, void *data) {
    return 0;
}

static int on_header_field(http_async_client* client, const char *at, size_t length, void *data) {
    return 0;
}

static int on_header_value(http_async_client* client, const char *at, size_t length, void *data) {
    return 0;
}

static int on_headers_complete(http_async_client* client, void *data) {
    return 0;
}

static int on_body(http_async_client* client, const char *at, size_t length, void *data) {
    YOU_LOG_DEBUG("%s", at);
    return 0;
}

static int on_message_complete(http_async_client* client, void *data) {
    YOU_LOG_DEBUG("");
    http_async_client_uninit(client);
    return 0;
}

static struct http_async_client_settings client_settings = {
    on_connect,
    on_message_begin,
    on_url,
    on_status,
    on_header_field,
    on_header_value,
    on_headers_complete,
    on_body,
    on_message_complete,

    NULL,
    NULL
};


static void on_timer_expire(uv_timer_t *handle) {

    http_async_client *client = http_async_client_init(uv_default_loop(), client_settings, NULL);
//    http_async_client_connect(client, "www.puacg.com", 80);
    http_async_client_connect(client, "127.0.0.1", 9013);
    
}

static void test_client() {
    uv_timer_init(uv_default_loop(), &timer_handle);
    uv_timer_start(&timer_handle, on_timer_expire, 1000, 0);
}


int main(int argc, char **argv) {

    http_server_config config;
    int err;
    
    memset(&config, 0, sizeof(config));
    config.bind_host = DEFAULT_BIND_HOST;
    config.bind_port = DEFAULT_BIND_PORT;
    config.idle_timeout = DEFAULT_IDLE_TIMEOUT;
    config.not_found_handler = not_found_handler;
    
    QUEUE_INIT(&config.handlers);
    
//    HTTP_SERVER_ADD_HANDLER(&config.handlers, "/", root_handler);
//    HTTP_SERVER_ADD_HANDLER(&config.handlers, "/meta", meta_handler);
    
    test_client();
    err = http_server_run(&config, uv_default_loop());
    if (err) {
        exit(1);
    }
    
    return 0;
}
