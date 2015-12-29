//
//  http_server_defs.h
//  YouSirCmd
//
//  Created by 吴建国 on 15/12/29.
//  Copyright © 2015年 wujianguo. All rights reserved.
//

#ifndef http_server_defs_h
#define http_server_defs_h

#include "uv.h"
#include <assert.h>
#include "http_parser.h"

/* ASSERT() is for debug checks, CHECK() for run-time sanity checks.
 * DEBUG_CHECKS is for expensive debug checks that we only want to
 * enable in debug builds but still want type-checked by the compiler
 * in release builds.
 */
#if defined(NDEBUG)
# define ASSERT(exp)
# define CHECK(exp)   do { if (!(exp)) abort(); } while (0)
# define DEBUG_CHECKS (0)
#else
# define ASSERT(exp)  assert(exp)
# define CHECK(exp)   assert(exp)
# define DEBUG_CHECKS (1)
#endif

#define UNREACHABLE() CHECK(!"Unreachable code reached.")

/* This macro looks complicated but it's not: it calculates the address
 * of the embedding struct through the address of the embedded struct.
 * In other words, if struct A embeds struct B, then we can obtain
 * the address of A by taking the address of B and subtracting the
 * field offset of B in A.
 */
#define CONTAINER_OF(ptr, type, field)                                        \
((type *) ((char *) (ptr) - ((char *) &((type *) 0)->field)))


enum http_connection_state {
    c_busy,  /* Busy; waiting for incoming data or for a write to complete. */
    c_done,  /* Done; read incoming data or write finished. */
    c_stop,  /* Stopped. */
    c_dead
};

typedef struct {
    enum http_connection_state rdstate;
    enum http_connection_state wrstate;
    unsigned int idle_timeout;
    
    uv_timer_t timer_handle;  /* For detecting timeouts. */
    uv_write_t write_req;
    
    union {
        uv_handle_t handle;
        uv_stream_t stream;
        uv_tcp_t tcp;
        uv_udp_t udp;
    } handle;
    uv_loop_t *loop;
    
} http_connection;

typedef struct {
    http_connection conn;
    http_parser parser;
    char buf[2048];
    ssize_t result;
    
} http_request;

typedef struct {
    http_connection conn;
    
    
} http_response;

#endif /* http_server_defs_h */