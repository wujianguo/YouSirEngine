//
//  you_parser.h
//  YouSirCmd
//
//  Created by wujianguo on 15/12/31.
//  Copyright © 2015年 wujianguo. All rights reserved.
//

#ifndef you_parser_h
#define you_parser_h

#include "uv.h"

typedef void (*you_parser_ready_cb)(int port);

int start_you_parser(uv_loop_t *loop, const char api[], int port, you_parser_ready_cb complete);

#endif /* you_parser_h */
