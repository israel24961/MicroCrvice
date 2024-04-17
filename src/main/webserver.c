#include "webserver.h"
#include <addresses.h>

struct Routes {
        int IndexLen;
        char *Index;
        int Error404Len;
        char *Error404;
        uint32_t FaviconLen;
        char *Favicon;
};

static struct Routes *root = NULL;
struct funcRoutes {
        char *route;
        void (*func)(struct evhttp_request *req, void *arg);
};
struct requestContext {
        char *ip;
        uint16_t port;
        struct evhttp_request *req;
        bool inStack; // Just in case some async stuff is needed
};

void Lctx(struct requestContext *ctx, char *fmt, ...)
{
        va_list args;
        va_start(args, fmt);
        __clean char *msg;
        vasprintf(&msg, fmt, args);
        L("[%s][%d] %s", ctx->ip, ctx->port, msg);
        va_end(args);
}

/** routes**/
void Index(struct evhttp_request *req, void *arg)
{
        struct requestContext *ctx = arg;
        var reply = evbuffer_new();
        evbuffer_add(reply, root->Index, root->IndexLen);
        evhttp_send_reply(req, HTTP_OK, "OK", reply);
        Lctx(ctx, "Index page served");
        evbuffer_free(reply);
}
void Error(struct evhttp_request *req, void *arg)
{
        struct requestContext *ctx = arg;
        var reply = evbuffer_new();
        evbuffer_add(reply, root->Error404, root->Error404Len);
        evhttp_send_reply(req, HTTP_NOTFOUND, "OK", reply);
        Lctx(ctx, "Error page served");
        evbuffer_free(reply);
        !ctx->inStack ?: free(ctx);
}
void generic_request_handler(struct evhttp_request *req, void *arg)
{
        struct requestContext *ctx = arg;
        var reply = evbuffer_new();
        // If / or /Index
        var uri = evhttp_request_get_uri(req);
        var uriHash = hash(uri, strlen(uri));
        __clean char *resp = NULL;
        // Sanity check
        var len = asprintf(&resp, "URI: %s URI Hash: %u", uri, uriHash);
        if (len < 0) {

                goto errorbye;
        }

        if (uriHash == 0) {
                Lctx(ctx, "URI is NULL");
                goto errorbye;
        } else if (uriHash == hash("/favicon.ico", strlen("/favicon.ico"))) {
                L("[%s][%d] Favicon", evhttp_request_get_host(req), evhttp_request_get_response_code(req));
                evbuffer_add(reply, root->Favicon, root->FaviconLen);
                evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "image/x-icon");
                evhttp_send_reply(req, HTTP_OK, "OK", reply);
        } else {
                goto errorbye;
        }

        evbuffer_free(reply);
        return;

errorbye:
        evbuffer_add(reply, resp, strlen(resp));
        evhttp_send_reply(req, HTTP_INTERNAL, "Yo wtf, nigga", reply);
        evbuffer_free(reply);
}

bool loadFiles();
bool setup_webserver() { return loadFiles(); }

void Router(struct evhttp_request *req, void *arg)
{
        struct requestContext ctx = {.req = req, .inStack = false};
        evhttp_connection_get_peer(evhttp_request_get_connection(req), &ctx.ip, &ctx.port);
        static struct funcRoutes routes[] = {{"/", Index}, {"/Index", Index}, {"/favicon.ico", generic_request_handler}, {"/Error", Error}};

        var uri = evhttp_request_get_uri(req);
        __clean char *uriClean = NULL;
        if (uri == nullptr) {
                Lctx(&ctx, "URI is NULL");
                goto errorbye;
        }

        var urlpath = evhttp_uri_get_path(evhttp_request_get_evhttp_uri(req));
        if (urlpath == nullptr) {
                Lctx(&ctx, "URL Path is NULL");
                goto errorbye;
        }
        assert(asprintf(&uriClean, "%s", urlpath) > 0);

        var query = evhttp_uri_get_query(evhttp_request_get_evhttp_uri(req));
        if (query) {
                __clean char *queryClean = NULL;
                assert(asprintf(&queryClean, "%s", query) > 0);
                __clean char *tmp = uriClean;
                assert(asprintf(&uriClean, "%s queries:%s", tmp, queryClean) > 0);
        } else {
                __clean char *tmp = uriClean;
                assert(asprintf(&uriClean, "%s queries:None", tmp) > 0);
        }
        Lctx(&ctx, "URI: %s", uriClean);

        // Insensitively compare the uri with the routes
        for (uint i = 0; i < sizeof(routes) / sizeof(struct funcRoutes); i++) {
                Ld("Comparing %s with %s", urlpath, routes[i].route);
                if (strcasecmp(urlpath, routes[i].route) == 0) {
                        Ld("Route found: %s", routes[i].route);
                        routes[i].func(req, &ctx);
                        return;
                }
        }
// If no route is found, return 404
errorbye:;
        Error(req, &ctx);
}

/** utils **/
bool loadFiles()
{
        char *path = "resources";

        root = malloc(sizeof(struct Routes));
        __clean char *indexPath;
        asprintf(&indexPath, "%s/index.html", path);
        var indexFd = fopen(indexPath, "r");
        if (indexFd == NULL) {
                Lf("Error opening index.html");
                return false;
        }
        fseek(indexFd, 0, SEEK_END);
        long indexSize = ftell(indexFd);
        fseek(indexFd, 0, SEEK_SET);
        root->Index = malloc(indexSize + 1);
        fread(root->Index, 1, indexSize, indexFd);
        fclose(indexFd);
        root->Index[indexSize] = 0;
        root->IndexLen = indexSize;

        __clean char *error404Path;
        asprintf(&error404Path, "%s/404.html", path);
        var error404Fd = fopen(error404Path, "r");
        if (error404Fd == NULL) {
                Lf("Error opening 404.html");
                return false;
        }
        fseek(error404Fd, 0, SEEK_END);
        long error404Size = ftell(error404Fd);
        fseek(error404Fd, 0, SEEK_SET);
        root->Error404 = malloc(error404Size + 1);
        fread(root->Error404, 1, error404Size, error404Fd);
        fclose(error404Fd);
        root->Error404[error404Size] = 0;
        root->Error404Len = error404Size;

        __clean char *faviconPath;
        asprintf(&faviconPath, "%s/favicon.ico", path);
        var faviconFd = fopen(faviconPath, "r");
        if (faviconFd == NULL) {
                Lf("Error opening favicon.ico");
                return false;
        }
        fseek(faviconFd, 0, SEEK_END);
        long faviconSize = ftell(faviconFd);
        fseek(faviconFd, 0, SEEK_SET);
        root->Favicon = malloc(faviconSize + 1);
        fread(root->Favicon, 1, faviconSize, faviconFd);
        fclose(faviconFd);
        root->Favicon[faviconSize] = 0;
        root->FaviconLen = faviconSize;
        return true;
}
