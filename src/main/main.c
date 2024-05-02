#include "main.h"
#include "database.h"
#include <wait.h>

FILE *ffmpegInput = NULL;
void libevLog(int severity, const char *msg)
{
        switch (severity) {
        case EVENT_LOG_DEBUG:
                Ld("%s", msg);
                break;
        case EVENT_LOG_MSG:
                L("%s", msg);
                break;
        case EVENT_LOG_WARN:
                Lw("%s", msg);
                break;
        case EVENT_LOG_ERR:
                Le("%s", msg);
                break;
        default:
                Lf("%s", msg);
                break;
        }
}

void ff0_ytKeyRequest(evutil_socket_t fd, short what, void *arg);
static inline void evClean(struct event **ptr) { event_free(*ptr); };
#define __evC __attribute__((cleanup(evClean)))
int main()
{
        event_enable_debug_mode();
        evthread_use_pthreads();
        event_set_log_callback(libevLog);
        var base = event_base_new();
        setup_webserver();
        var evs = init_webserver(base);

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
        // Init DBConection
        var conn = DatabaseInit("localhost", "tfg", "tfg", "tfg", 3306);
        if (!conn) {
                Le("Failed to connect to database");
                assert(false);
        }

        var http_port = 12345;
        var http_addr = "0.0.0.0";

        var http = evhttp_new(base);
        evhttp_set_timeout(http, 20);
        evhttp_bind_socket(http, http_addr, http_port);
        evhttp_set_gencb(http, Router, conn);
        // Buffer size
        evhttp_set_max_headers_size(http, 1024 * 1024);
        evhttp_set_max_body_size(http, 1024 * 1024 * 1024);

        var signint = evsignal_new(base, SIGINT, signal_cb, base);
        event_add(signint, NULL);

        L("Queued webserver on %s:%d", http_addr, http_port);
        return (struct structInitWebserver){http, signint};
}
////////////////////////////////////////////////////////////////////////////////

void ff0_ytKeyRequest(evutil_socket_t fd, short what, void *arg)
{
        struct event_base *base = arg;
        var cmd = "pass google/key/yt";
        var keyPipe = popen(cmd, "r");
        if (!keyPipe) {
                Le("'%s' command failed", cmd);
                return;
        }
        // Add a eventhandler for the keyPipe
        var keyEvent = event_new(base, fileno(keyPipe), EV_READ | EV_PERSIST, ff0_ytKeyRequest, base);
        event_add(keyEvent, NULL);
}
struct structInitFFmpeg setup_ffmpegStream()
{
        struct structInitFFmpeg ffmpeg = {};
        var pip = popen("ffmpeg -y -loglevel verbose  -i -  ouput.webm", "w");
        if (!pip) {
                Le("Failed to open pipe");
                return ffmpeg;
        }
        fflush(pip);
        // Read file example.mp4
        // FILE *file = fopen("resources/example.mp4", "rb");
        // if (!file) {
        //         Le("Failed to open file");
        //         assert(false);
        // }
        //
        // // Batch read 2KB, then pause for 1s
        // char buffer[500000];
        // size_t bytesRead = 0;
        // while ((bytesRead = fread(buffer, 1, sizeof(buffer), file))) {
        //         L("Read %ld bytes", bytesRead);
        //         var written = fwrite(buffer, 1, bytesRead, pip);
        //         L("Wrote %ld bytes", written);
        // }
        //
        // // Close file
        // fclose(file);

        ffmpeg.input = pip;
        // var cmd = ""
        return ffmpeg;
}
