#include "addresses.h"
#include "webserver.h"
#include <0_GlobalIncludes.h>
#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/thread.h>

struct structInitWebserver {
        struct evhttp *http;
        struct event *signint;
};
struct structInitWebserver init_webserver(struct event_base *base);
 
struct structInitFFmpeg{ 
    FILE *input;
};
struct structInitFFmpeg setup_ffmpegStream();
