//
//  http_async_client.h
//  YouSirCmd
//
//  Created by 吴建国 on 15/12/30.
//  Copyright © 2015年 wujianguo. All rights reserved.
//

#ifndef http_async_client_h
#define http_async_client_h

#include "http_server_defs.h"

#define MAX_HOST_LEN 128

typedef struct http_async_client http_async_client;

typedef int (*http_async_client_data_cb) (http_async_client*, const char *at, size_t length);
typedef int (*http_async_client_cb) (http_async_client*);

struct http_async_client_settings {
    http_async_client_cb      on_connect;
    http_async_client_cb      on_message_begin;
    http_async_client_data_cb on_url;
    http_async_client_data_cb on_status;
    http_async_client_data_cb on_header_field;
    http_async_client_data_cb on_header_value;
    http_async_client_cb      on_headers_complete;
    http_async_client_data_cb on_body;
    http_async_client_cb      on_message_complete;
    /* When on_chunk_header is called, the current chunk length is stored
     * in parser->content_length.
     */
    http_async_client_cb      on_chunk_header;
    http_async_client_cb      on_chunk_complete;
};

http_async_client* http_async_client_init(uv_loop_t *loop, struct http_async_client_settings settings);

int http_async_client_connect(http_async_client *client, const char host[MAX_HOST_LEN], unsigned short port);

int http_async_client_send(http_async_client *client, const char *buf, size_t len);

void http_async_client_uninit(http_async_client *client);

#endif /* http_async_client_h */
