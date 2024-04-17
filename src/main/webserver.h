#pragma once
#include <0_GlobalIncludes.h>
#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/http.h>

void Router(struct evhttp_request *req, void *arg);
bool setup_webserver();
