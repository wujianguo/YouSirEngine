//
//  you_parser.c
//  YouSirCmd
//
//  Created by wujianguo on 15/12/31.
//  Copyright © 2015年 wujianguo. All rights reserved.
//

#include "you_parser.h"
#include "http_connection.h"
#include "http_parser.h"
#include <stdlib.h>
#include <pthread.h>
#include <Python/Python.h>

typedef struct {
    char api[MAX_URL_LEN];
    char host[MAX_HOST_LEN];
    
    int port;
    you_parser_ready_cb complete;
    
    char *script;
    size_t pos;
    
} you_parser_struct;


static void* python_script_thread(void* params) {
    you_parser_struct *y = (you_parser_struct*)params;
    // todo: notify server start
    Py_Initialize();
    PyObject *p_code = Py_CompileString(y->script, "you_parser", Py_file_input);
    if (p_code) {
        PyObject *p_module = PyImport_ExecCodeModule("you_parser", p_code);
        if (p_module) {
            PyObject *p_func = PyObject_GetAttrString(p_module, "start_server");
            if (p_func && PyCallable_Check(p_func)) {
                PyObject *p_port = PyInt_FromLong(y->port);
                PyObject *p_args = PyTuple_New(1);
                PyTuple_SetItem(p_args, 0, p_port);
                PyObject_CallObject(p_func, p_args);
                
                Py_DecRef(p_port);
                Py_DecRef(p_args);
            }
            Py_XDECREF(p_func);
            Py_DecRef(p_module);
        }
        Py_DecRef(p_code);
    }
    
    Py_Finalize();
    free(y->script);
    free(y);
    YOU_LOG_ERROR("");
    // todo: notify server stop or error
    return NULL;
}

static void run_python_script(you_parser_struct *you_parser) {
    pthread_t tid;
    pthread_create(&tid, NULL, python_script_thread, (void*)you_parser);
    you_parser->complete(you_parser->port);
}


static void on_connect(http_connection *conn, void *user_data) {
    you_parser_struct *y = (you_parser_struct*)user_data;

    const char format[] = "GET /script/you_parser.py HTTP/1.1\r\n"
    "Host: %s\r\n"
    "Connection: close\r\n"
    "Cache-Control: no-cache\r\n"
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
    "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.106 Safari/537.36\r\n"
    "Accept-Encoding: gzip, deflate\r\n"
    "Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.6,en;q=0.4\r\n"
    "\r\n";
    
    char header[MAX_REQUEST_HEADER_LEN] = {0};
    snprintf(header, MAX_REQUEST_HEADER_LEN, format, y->host);
    http_connection_send(conn, header, strlen(header));
}

static void on_send(http_connection *conn, void *user_data) {

}

static void on_header_complete(http_connection *conn, struct http_header *header, void *user_data) {
    you_parser_struct *y = (you_parser_struct*)user_data;
    y->script = (char*)malloc(header->parser.content_length + 1);
    memset(y->script, 0, header->parser.content_length + 1);
}

static void on_body(http_connection *conn, const char *at, size_t length, void *user_data) {
    you_parser_struct *y = (you_parser_struct*)user_data;
    memcpy(y->script + y->pos, at, length);
    y->pos += length;
}

static void on_message_complete(http_connection *conn, void *user_data) {
    you_parser_struct *y = (you_parser_struct*)user_data;
    YOU_LOG_DEBUG("\n%s", y->script);
    free_http_connection(conn);
    run_python_script(y);
}

static struct http_connection_settings settings = {
    on_connect,
    on_send,
    on_header_complete,
    on_body,
    on_message_complete
};

int start_you_parser(uv_loop_t *loop, const char api[], int port, you_parser_ready_cb complete) {
    struct http_parser_url url = {0};
    http_parser_url_init(&url);
    http_parser_parse_url(api, strlen(api), 0, &url);
    if (!(url.field_set & (1<<UF_HOST)))
        return -1;

    CHECK(url.field_data[UF_HOST].len <= MAX_HOST_LEN);
    
    you_parser_struct *y = (you_parser_struct*)malloc(sizeof(you_parser_struct));
    memset(y, 0, sizeof(you_parser_struct));
    y->complete = complete;
    y->port = port;
    memcpy(y->host, api + url.field_data[UF_HOST].off, url.field_data[UF_HOST].len);
    memcpy(y->api, api, strlen(api));
    http_connection *conn = create_http_connection(loop, settings, y);
    http_connection_connect(conn, y->host, url.port);
    return 0;
}

