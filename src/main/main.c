#include "main.h"

// TODO: add file watchers for Index and Error404, when in DEBUG mode

static inline void evClean(struct event **ptr) { event_free(*ptr); };
#define __evC __attribute__((cleanup(evClean)))

int main()
{
        var base = event_base_new();
        setup_webserver();
        var evs = init_webserver(base);

        var ffmpeg = setup_ffmpegStream();


        event_base_dispatch(base);

        evhttp_free(evs.http);
        event_free(evs.signint);
        event_base_free(base);

        return 0;
}

/** Console stuff **/
void timer2secs(evutil_socket_t ev, short what, void *p)
{
        int *pcalled = (int *)p;
        *pcalled = 0;
};
void signal_cb(evutil_socket_t fd, short what, void *arg)
{
        static int called = 0;
        static bool isTimerActive = false;
        struct event_base *base = arg;
        // If ctrl+c is pressed twice, exit the program
        static struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
        if (!isTimerActive) {
                var ev = event_base_once(base, -1, EV_TIMEOUT, timer2secs, &called, &tv);
        }
        called++;
        if (called == 3)
                event_base_loopbreak(base);
        else
                L("Press ctrl+c (3 times to exit, %d/3)", called);
}

struct structInitWebserver init_webserver(struct event_base *base)
{
        var http_port = 12345;
        var http_addr = "0.0.0.0";

        var http = evhttp_new(base);
        evhttp_bind_socket(http, http_addr, http_port);
        evhttp_set_gencb(http, Router, NULL);

        var signint = evsignal_new(base, SIGINT, signal_cb, base);
        event_add(signint, NULL);

        L("Queued webserver on %s:%d", http_addr, http_port);
        return (struct structInitWebserver){http, signint};
}

struct structInitFFmpeg setup_ffmpegStream()
{
        struct structInitFFmpeg ffmpeg = {};
        // var cmd = ""
        return ffmpeg;
}
