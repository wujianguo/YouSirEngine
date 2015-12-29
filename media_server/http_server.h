//
//  http_server.h
//  YouSirCmd
//
//  Created by 吴建国 on 15/12/29.
//  Copyright © 2015年 wujianguo. All rights reserved.
//

#ifndef http_server_h
#define http_server_h

#include "uv.h"
#include "queue.h"
#include "http_server_defs.h"


typedef void (*http_session_complete_cb)(http_request *req);
typedef void (*http_handler_func)(http_request *req, http_response *resp, http_session_complete_cb complete);

typedef struct {
    QUEUE node;
    
    http_handler_func handler;
    char path[128];
} http_handler_setting;

typedef struct {
    const char *bind_host;
    unsigned short bind_port;
    unsigned int idle_timeout;
    
    QUEUE handlers;
} http_server_config;

int http_server_run(const http_server_config *cf, uv_loop_t *loop);

#endif /* http_server_h */
