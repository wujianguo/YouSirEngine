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
#include "http_server.h"

#define DEFAULT_BIND_HOST     "127.0.0.1"
#define DEFAULT_BIND_PORT     9013
#define DEFAULT_IDLE_TIMEOUT  (5 * 1000)


#include "tree.h"
#include "queue.h"

const static char default_http[] = "HTTP/1.1 200 OK\r\n"
"Server: YouSir/2\r\n"
"Content-type: text/plain\r\n"
"Content-Length: 5\r\n"
"\r\n"
"hello";


//const char format[] = "HTTP/1.1 404 Not Found\r\n"
//"Server: YouSir/2\r\n"
//"Content-type: text/plain\r\n"
//"Content-Length: %lu\r\n"
//"\r\n"
//"%s";

//const char format[] =     "ache\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
//"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.106 Safari/537.36\r\n"
//"Accept-Encoding: gzip, deflate\r\n"
//"Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.6,en;q=0.4\r\n"
//"\r\n";

//const char format[] = "GET /1.json HTTP/1.1\r\n"
//"Host: 127.0.0.1\r\n"
//"Connection: keep-alive\r\n"
//"Cache-Control: no-c";

//const char format[] = "GET /1.json HTTP/1.1\r\n"
//"Host: www.puacg.com\r\n"
//"Connection: keep-alive\r\n"
//"Cache-Control: no-cache\r\n"
//"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
//"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.106 Safari/537.36\r\n"
//"Accept-Encoding: gzip, deflate\r\n"
//"Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.6,en;q=0.4\r\n"
//"\r\n";



#define HTTP_SERVER_ADD_HANDLER(queue, custom_path, custom_handler)     \
    do {                                                                \
        http_handler_setting setting = {0};                             \
        strncpy(setting.path, custom_path, sizeof(setting.path));       \
        setting.on_send = custom_handler##_on_send;                               \
        setting.on_body = custom_handler##_on_body;                               \
        setting.on_message_complete = custom_handler##_on_message_complete;                               \
        setting.on_header_complete = custom_handler##_on_header_complete;                               \
        QUEUE_INIT(&setting.node);                                      \
        QUEUE_INSERT_TAIL(queue, &setting.node);                        \
    }                                                                   \
    while(0)





// /
static void root_handler_on_header_complete(http_request *req) {
    
}

static void root_handler_on_body(http_request *req, const char *at, size_t length) {
    
}

static void root_handler_on_message_complete(http_request *req) {
    http_connection_send(req->conn, default_http, strlen(default_http));
}

static void root_handler_on_send(http_request *req) {
    req->complete(req);
}

// meta
static void meta_handler_on_header_complete(http_request *req) {
    
}

static void meta_handler_on_body(http_request *req, const char *at, size_t length) {
    
}

static void meta_handler_on_message_complete(http_request *req) {
    http_connection_send(req->conn, default_http, strlen(default_http));
}

static void meta_handler_on_send(http_request *req) {
    req->complete(req);
}




uv_timer_t timer_handle;

static int conn2_step = 0;

static void on_timer_expire2(uv_timer_t *handle) {
    http_connection *conn = (http_connection*)handle->data;
    const char format[] =     "ache\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
    "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.106 Safari/537.36\r\n"
    "Accept-Encoding: gzip, deflate\r\n"
    "Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.6,en;q=0.4\r\n"
    "\r\n";
    http_connection_send(conn, format, strlen(format));
}

static void on_connect(http_connection *conn, void *user_data) {
    if (user_data == NULL) {
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
    } else {
        const char format[] = "GET /1.json HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Connection: keep-alive\r\n"
        "Cache-Control: no-c";
        http_connection_send(conn, format, strlen(format));
    }
}

static void on_send(http_connection *conn, void *user_data) {
    if (user_data != NULL) {
        if (conn2_step == 0) {
            conn2_step = 1;
            timer_handle.data = conn;
            uv_timer_start(&timer_handle, on_timer_expire2, 1000, 0);
        }
    }
}

static void on_header_complete(http_connection *conn, struct http_header *header, void *user_data) {
    
}

static void on_body(http_connection *conn, const char *at, size_t length, void *user_data) {
    YOU_LOG_DEBUG("%p:%s", conn, at);
}

static void on_message_complete(http_connection *conn, void *user_data) {
    free_http_connection(conn);
}

static struct http_connection_settings settings = {
    on_connect,
    on_send,
    on_header_complete,
    on_body,
    on_message_complete
};

static void on_timer_expire(uv_timer_t *handle) {
    http_connection *conn = create_http_connection(handle->loop, settings, NULL);
    http_connection_connect(conn, "www.puacg.com", 80);
    
    http_connection *conn2 = create_http_connection(handle->loop, settings, (void*)1);
    http_connection_connect(conn2, "127.0.0.1", 9013);
}

static void test_client() {
    uv_timer_init(uv_default_loop(), &timer_handle);
    uv_timer_start(&timer_handle, on_timer_expire, 1000, 0);
}

#include "media_handler.h"

int main(int argc, char **argv) {

    http_server_config config;
    int err;
    
    memset(&config, 0, sizeof(config));
    config.bind_host = DEFAULT_BIND_HOST;
    config.bind_port = DEFAULT_BIND_PORT;
    config.idle_timeout = DEFAULT_IDLE_TIMEOUT;
    
    QUEUE_INIT(&config.handlers);
    
    HTTP_SERVER_ADD_HANDLER(&config.handlers, "/", root_handler);
    HTTP_SERVER_ADD_HANDLER(&config.handlers, "/meta", meta_handler);
    HTTP_SERVER_ADD_HANDLER(&config.handlers, "/media", media_handler);
    
    
    test_client();
    err = http_server_run(&config, uv_default_loop());
    if (err) {
        exit(1);
    }
    
    return 0;
}
