//
//  media_handler.c
//  YouSirCmd
//
//  Created by 吴建国 on 15/12/31.
//  Copyright © 2015年 wujianguo. All rights reserved.
//

#include "media_handler.h"
#include <stdlib.h>

enum media_handler_state {
    s_parse_url,
    s_media_data
};

typedef struct {
    enum media_handler_state state;
    http_request *req;
    
    http_connection *remote;
} media_handler;


static void do_media_data(media_handler *h);

static void on_connect(http_connection *conn, void *user_data) {
    media_handler *h = (media_handler*)user_data;
    if (h->state == s_parse_url) {
        const char format[] = "GET /1.json HTTP/1.1\r\n"
        "Host: www.puacg.com\r\n"
        "Connection: keep-alive\r\n"
        "Cache-Control: no-cache\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
        "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.106 Safari/537.36\r\n"
        "Accept-Encoding: gzip, deflate\r\n"
        "Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.6,en;q=0.4\r\n"
        "\r\n";
        http_connection_send(conn, format, strlen(format));
    } else if (h->state == s_media_data) {
        const char format[] = "GET /1.json HTTP/1.1\r\n"
        "Host: www.puacg.com\r\n"
        "Connection: keep-alive\r\n"
        "Cache-Control: no-cache\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
        "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.106 Safari/537.36\r\n"
        "Accept-Encoding: gzip, deflate\r\n"
        "Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.6,en;q=0.4\r\n"
        "\r\n";
        http_connection_send(conn, format, strlen(format));
    }
    
}

static void on_send(http_connection *conn, void *user_data) {

}

static void on_header_complete(http_connection *conn, struct http_header *header, void *user_data) {

}

static void on_body(http_connection *conn, const char *at, size_t length, void *user_data) {

}

static void on_message_complete(http_connection *conn, void *user_data) {
    media_handler *h = (media_handler*)user_data;
    if (h->state == s_parse_url) {
        h->state = s_media_data;
        free_http_connection(conn);
        do_media_data(h);
    }
}

static struct http_connection_settings settings = {
    on_connect,
    on_send,
    on_header_complete,
    on_body,
    on_message_complete
};

static void do_media_data(media_handler *h) {
    h->remote = create_http_connection(h->req->loop, settings, h);
    http_connection_connect(h->remote, "", 80);
}

void media_handler_on_header_complete(http_request *req) {
    media_handler *h = (media_handler*)malloc(sizeof(media_handler));
    memset(h, 0, sizeof(media_handler));
    h->state = s_parse_url;
    h->remote = create_http_connection(req->loop, settings, h);
    http_connection_connect(h->remote, "www.puacg.com", 80);
}

void media_handler_on_body(http_request *req, const char *at, size_t length) {
    
}

void media_handler_on_message_complete(http_request *req) {
    const char default_http[] = "HTTP/1.1 200 OK\r\n"
    "Server: YouSir/2\r\n"
    "Content-type: text/plain\r\n"
    "Content-Length: 5\r\n"
    "\r\n"
    "hello";
    http_connection_send(req->conn, default_http, strlen(default_http));
}

void media_handler_on_send(http_request *req) {
    req->complete(req);
}