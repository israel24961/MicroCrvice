#pragma once
#include <0_GlobalIncludes.h>
#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/http_struct.h>
#include <event2/keyvalq_struct.h>

void Router(struct evhttp_request *req, void *arg);
bool setup_webserver();
typedef struct {
        bool err;
        i32 val;
} b_i32;
typedef struct {
        bool err;
        char *val;
        u32 len;
} b_str;

b_i32 FieldIntQuery(char *query, char *field);
void RequestToken(struct evhttp_request *req, void *arg);

