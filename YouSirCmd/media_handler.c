//
//  media_handler.c
//  YouSirCmd
//
//  Created by 吴建国 on 15/12/30.
//  Copyright © 2015年 wujianguo. All rights reserved.
//

#include "media_handler.h"
#include "http_async_client.h"
#include <stdlib.h>

enum media_handler_state {
    s_parse_real_url,
    s_media_data
};

typedef struct {
    enum media_handler_state state;
    http_async_client *client;
    http_request *req;
} media_handler_struct;

static void do_next(media_handler_struct *h);

static int on_connect(http_async_client* client, void *data) {
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
    media_handler_struct *h = (media_handler_struct*)data;
    http_async_client_uninit(client);
    do_next(h);
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

static void do_media_data(media_handler_struct *h) {
    http_async_client_init(h->req->conn.loop, client_settings, h);
}

static void do_parse_real_url(media_handler_struct *h) {
    h->state = s_parse_real_url;
    h->client = http_async_client_init(h->req->conn.loop, client_settings, h);
    http_async_client_connect(h->client, "www.puacg.com", 80);
}

static void do_kill(media_handler_struct *h) {
    
}

static void do_next(media_handler_struct *h) {
    switch (h->state) {
        case s_parse_real_url:
            do_media_data(h);
            break;
        case s_media_data:
            break;
        default:
            UNREACHABLE();
    }
}

void handler_media(http_request *req, http_session_complete_cb complete) {
    media_handler_struct *h = (media_handler_struct*)malloc(sizeof(media_handler_struct));
    memset(h, 0, sizeof(media_handler_struct));
    h->req = req;
    do_parse_real_url(h);
}

