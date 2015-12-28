//
//  main.c
//  YouSirCmd
//
//  Created by wujianguo on 15/12/28.
//  Copyright © 2015年 wujianguo. All rights reserved.
//

#include <stdio.h>
#include "uv.h"

int main(int argc, const char * argv[]) {
    // insert code here...
    printf("Hello, World!\n");
    uv_run(uv_default_loop(), UV_RUN_DEFAULT);
    return 0;
}
