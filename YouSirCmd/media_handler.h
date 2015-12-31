//
//  media_handler.h
//  YouSirCmd
//
//  Created by 吴建国 on 15/12/31.
//  Copyright © 2015年 wujianguo. All rights reserved.
//

#ifndef media_handler_h
#define media_handler_h

#include "http_server.h"

void media_handler_on_header_complete(http_request *req);

void media_handler_on_body(http_request *req, const char *at, size_t length);

void media_handler_on_message_complete(http_request *req);

void media_handler_on_send(http_request *req);

#endif /* media_handler_h */
