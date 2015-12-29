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

#define DEFAULT_BIND_HOST     "127.0.0.1"
#define DEFAULT_BIND_PORT     9013
#define DEFAULT_IDLE_TIMEOUT  (60 * 1000)


#include "tree.h"
#include "queue.h"

void root_handler(http_request *req, http_response *resp, http_session_complete_cb complete) {
    YOU_LOG_DEBUG("%s", req->buf);
    char url[1024] = {0};
    memcpy(url, req->buf + req->url_off, req->url_len);
    YOU_LOG_DEBUG("url:%s", url);
    
    char body[1024] = {0};
    memcpy(body, req->buf + req->body_off, req->body_len);
    YOU_LOG_DEBUG("body:%s", body);
}

void meta_handler(http_request *req, http_response *resp, http_session_complete_cb complete) {
    YOU_LOG_DEBUG("");    
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
    
    err = http_server_run(&config, uv_default_loop());
    if (err) {
        exit(1);
    }
    
    return 0;
}
