#include "webserver.h"
#include "database.h"
#include <addresses.h>
#include <event2/http.h>

struct Routes {
        int IndexLen;
        char *Index;
        int Error404Len;
        char *Error404;
        uint32_t FaviconLen;
        char *Favicon;
};
char *HTTPMETHODS[] = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE", "CONNECT", "PATCH"};

void dbClean(MYSQL **ptr) { mysql_close(*ptr); }
void dbstmtClean(MYSQL_STMT **ptr) { mysql_stmt_close(*ptr); }
#define __cleanSTMT __attribute__((cleanup(dbstmtClean)))

void ReturnCodeBody(struct evhttp_request *req, int code, char *fmt, ...)
{
        var reply = evbuffer_new();
        va_list args;
        va_start(args, fmt);
        evbuffer_add_vprintf(reply, fmt, args);
        va_end(args);
        evhttp_send_reply(req, code, nullptr, reply);
        evbuffer_free(reply);
}

void ReturnCode(struct evhttp_request *req, int code, char *msg)
{
        var reply = evbuffer_new();
        evhttp_send_reply(req, code, msg, reply);
        evbuffer_free(reply);
}

/**
 * @brief Send a reply to the client
 * Frees the evbuffer
 * @param reply The evbuffer to send, if NULL, this function will make a new one and free it
 **/
void reply_ReturnCode(struct evhttp_request *req, struct evbuffer *reply, int code, char *msg)
{
        if (reply == nullptr) {
                reply = evbuffer_new();
        }
        evhttp_send_reply(req, code, msg, reply);
        evbuffer_free(reply);
}
const char *getMethod(enum evhttp_cmd_type method)
{
        var index = log2(method);
        var len = sizeof(HTTPMETHODS) / sizeof(char *);
        if (index >= len || index < 0) {
                return "UNKNOWN";
        }
        return HTTPMETHODS[(int)index];
}

static struct Routes *root = NULL;
struct funcRoutes {
        char *route;
        void (*func)(struct evhttp_request *req, void *arg);
        enum evhttp_cmd_type method;
};
struct requestContext {
        MYSQL *conn;
        char *ip;
        uint16_t port;
        struct evhttp_request *req;
        bool isRAM; // Just in case some async stuff is needed
        struct timespec time;
};

#define Lctx(ctx, fmt, ...) L("[%s][%d]" fmt, (ctx)->ip, (ctx)->port __VA_OPT__(, ) __VA_ARGS__);

/** routes**/
void Index(struct evhttp_request *req, void *arg)
{
        struct requestContext *ctx = arg;
        var reply = evbuffer_new();
        evbuffer_add(reply, root->Index, root->IndexLen);
        evhttp_send_reply(req, HTTP_OK, "OK", reply);
        evbuffer_free(reply);
        struct timeval end;
        gettimeofday(&end, NULL);
}
void Error(struct evhttp_request *req, void *arg)
{
        struct requestContext *ctx = arg;
        var reply = evbuffer_new();
        evbuffer_add(reply, root->Error404, root->Error404Len);
        evhttp_send_reply(req, HTTP_NOTFOUND, "OK", reply);
        Lctx(ctx, "Error page served");
        evbuffer_free(reply);
        !ctx->isRAM ?: free(ctx);
}
/*
 * Generic request handler
 * Used for resources like favicon.ico
 */
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

static int counter = 0;

void Counter(struct evhttp_request *req, void *arg)
{
        struct requestContext *ctx = arg;
        var reply = evbuffer_new();
        var querytmp = evhttp_uri_get_query(evhttp_request_get_evhttp_uri(req));
        {
                if (querytmp == nullptr)
                        goto errorbye;
        }
        var idVal = FieldIntQuery(querytmp, "id");
        if (idVal.err)
                goto errorbye;
        counter += idVal.val;
errorbye:;
        __clean char *msg;
        var len = asprintf(&msg, "%d", counter);
        assert(len > 0);
        evbuffer_add(reply, msg, len);
        evhttp_send_reply(req, HTTP_OK, "OK", reply);
        Lctx(ctx, "Counter=%d", counter);
        evbuffer_free(reply);
}

bool loadFiles();
bool setup_webserver() { return loadFiles(); }

void sendMp4Pipe(struct evhttp_request *req, void *arg)
{
        struct requestContext ctx = {.req = req, .isRAM = false};
        var conn = evhttp_request_get_connection(req);
        if (!conn) {
                L("Connection is NULL");
                goto errorbye;
        }
        var buffEv = evhttp_connection_get_bufferevent(conn);
        if (!buffEv) {
                L("BufferEvent is NULL");
                goto errorbye;
        }

        return;
errorbye:;

        return;
}
#include <json-c/json.h>
void genVideoPipe(struct evhttp_request *req, void *arg)
{
        struct requestContext *ctx = arg;
        Lctx(ctx, "Generating video");
        var reply = evbuffer_new();
        var fakeLink = "http://localhost:12345/stream/1234567890";

        var json = json_object_new_object();
        json_object_object_add(json, "link", json_object_new_string(fakeLink));
        json_object_object_add(json, "status", json_object_new_string("OK"));
        var jsonStr = json_object_to_json_string(json);

        evbuffer_add(reply, jsonStr, strlen(jsonStr));
        evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/json");
        evhttp_send_reply(req, HTTP_OK, "OK", reply);
        evbuffer_free(reply);
        json_object_put(json);
        return;
errorbye:;
        return;
}

struct videos {
        char *name;
        char *link;
        char *description;
};
// Current Videos available
struct videos CurrentVideos[] = {};

void listVideos(struct evhttp_request *req, void *arg)
{
        struct timeval start, end;
        gettimeofday(&start, NULL);
        struct requestContext *ctx = arg;
        var reply = evbuffer_new();
        struct videos vids = {.name = "Video", .link = "http://localhost:12345/stream/1234567890", .description = "This is a video 10"};
        var rnd = 10000;
        Lctx(ctx, "Listing videos %d times", rnd);
        for (uint i = 0; i < rnd; i++) {
                evbuffer_add_printf(reply, "<div> <a href=\"%s\">%s %d </a> <p>%s</p> </div>", vids.link, vids.name, i, vids.description);
        }
        gettimeofday(&end, NULL);
        Lctx(ctx, "Time taken adding divs %f ms ", (end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000.0);

        evhttp_send_reply(req, HTTP_OK, "OK", reply);
        evbuffer_free(reply);
        return;
}

struct loginDTO {
        int salt; // Random number
        char *user;
        char *pass;
};
b_str FieldStrQuery(char *query, char *field);
// Returns the trimmed portion of the string
b_str *stringTRIM(b_str *str)
{
        if (str->val == NULL)
                return str;
        var start = str->val;
        var end = str->val + str->len - 1;
        while (isspace(*start) && start < end)
                start++;
        while (isspace(*end) && end > start)
                end--;
        str->val = start;
        str->len = end - start + 1;
        return str;
}
// Returns false if val is null
bool isAlphaNumeric(b_str *str)
{
        if (str->err)
                return false;
        if (str->len == 0 || str->val == nullptr)
                return (str->err = true, false);

        for (u32 i = 0; i < str->len; i++) {
                if (!isalnum(str->val[i]))
                        return false;
        }

        return true;
}
#define STR(x) #x
#define MSTR(x) STR(x)

// Returns error message if invalid
char *login_validate(b_str *user, b_str *pass)
{
        if (user->len > kDB_LOGINMAX_USER || user->len <= 0 || user->val == nullptr)
                return "More than " MSTR(kDB_LOGINMAX_USER) " characters or less than 1";
        if (!isAlphaNumeric(stringTRIM(user)))
                return "User is not alphanumeric";
        if (user->len < 8)
                return "User is less than 8 characters";

        if (pass->len > kDB_LOGINMAX_PASS || pass->len <= 0 || pass->val == nullptr)
                return "More than " MSTR(kDB_LOGINMAX_PASS) " characters or less than 1";
        var preTrimLen = pass->len;
        if (preTrimLen != pass->len)
                return "Password has leading or trailing spaces";
        // Other policies
        if (pass->len < 8)
                return "Password is less than 8 characters";
        return NULL;
}

#include <uuid/uuid.h>
void Login(struct evhttp_request *req, void *arg)
{
        struct requestContext *ctx = arg;
        var input = evhttp_request_get_input_buffer(req);
        if (input == nullptr) {
                L("Input buffer is NULL");
                return ReturnCode(req, 413, "I'm kinda dead inside");
        }
        var len = evbuffer_get_length(input);
        if (len == 0) {
                L("Input buffer is empty");
                ReturnCode(req, 400, "I'm kinda dead inside");
                return;
        }
        // __clean char *body = malloc(len + 1);
        char body[len + 1];
        evbuffer_remove(input, body, len);
        body[len] = 0;
        L("Body: %s", body);
        // Parse the Body
        var user = FieldStrQuery(body, "user");
        var pass = FieldStrQuery(body, "pass");

        var msg = login_validate(&user, &pass);
        if (msg)
                return ReturnCodeBody(req, 422, "<h3 id='error'>%s</h3>", msg);

        // using the mariadb connection
        var conn = ctx->conn;
        assert(conn);
        var query = "SELECT u.Id FROM users u WHERE u.user = ? AND u.pass = ?";
        __cleanSTMT var stmt = mysql_stmt_init(conn);
        if (!stmt) {
                Lctx(ctx, "Stmt is NULL");
                return ReturnCode(req, 500, "I'm kinda dead inside");
        }
        var prep = mysql_stmt_prepare(stmt, query, strlen(query));
        if (prep) {
                Lctx(ctx, "Check the query, dude 🦆 %s", mysql_stmt_error(stmt));
                return ReturnCode(req, 500, "I'm kinda dead inside");
        }
        MYSQL_BIND bind[2] = {{.buffer_type = MYSQL_TYPE_STRING, .buffer = user.val, .buffer_length = user.len, .is_null = 0, .length = 0},
                              {.buffer_type = MYSQL_TYPE_STRING, .buffer = pass.val, .buffer_length = pass.len, .is_null = 0, .length = 0}};

        // Bind the parameters
        if (mysql_stmt_bind_param(stmt, bind)) {
                Lctx(ctx, "Bind failed");
                return ReturnCode(req, 500, "I'm kinda dead inside");
        }
        if (mysql_stmt_execute(stmt)) {
                Lctx(ctx, "DB execution failed");
                return ReturnCode(req, 500, "I'm kinda dead inside");
        }

        i32 id;
        bool isNull;
        u64 length;
        MYSQL_BIND result[] = {{.buffer_type = MYSQL_TYPE_LONG, .buffer = &id, .is_null = &isNull, .length = &length}};
        if (mysql_stmt_bind_result(stmt, result)) {
                Lctx(ctx, "Bind result failed");
                return ReturnCode(req, 500, "I'm kinda dead inside");
        }
        var fetch = mysql_stmt_fetch(stmt);

        if (fetch == 1 || fetch == MYSQL_NO_DATA) {
                Lctx(ctx, "Login failed %s", mysql_stmt_error(stmt));
                return ReturnCode(req, 401, "Not valid, pal");
        }
        if (isNull || id == 0 || length == 0) {
                Lctx(ctx, "Login failed");
                return ReturnCode(req, 401, "Not valid, pal");
        }

        mysql_stmt_free_result(stmt);

        Lctx(ctx, "Login successful %d", id);
        // Make a token
        uuid_t uuid;
        uuid_generate(uuid);
        query = "update logins set invalidated_at = now() where user_id = ? and invalidated_at is null";
        prep = mysql_stmt_prepare(stmt, query, strlen(query));
        if (prep) {
                Lctx(ctx, "Check the query, 🦆 %s", mysql_stmt_error(stmt));
                return ReturnCode(req, 500, "I'm kinda dead inside");
        }
        MYSQL_BIND bind2[] = {{.buffer_type = MYSQL_TYPE_LONG, .buffer = &id, .is_null = 0, .length = 0},
                              {.buffer_type = MYSQL_TYPE_BLOB, .buffer = uuid, .buffer_length = sizeof(uuid), .is_null = 0, .length = 0}};
        if (mysql_stmt_bind_param(stmt, bind2)) {
                Lctx(ctx, "Bind token failed %s", mysql_stmt_error(stmt));
                return ReturnCode(req, 500, "I'm kinda dead inside");
        }
        if (mysql_stmt_execute(stmt)) {
                Lctx(ctx, "DB execution failed %s", mysql_stmt_error(stmt));
                return ReturnCode(req, 500, "I'm kinda dead inside");
        }
        var updatedMeta = mysql_stmt_affected_rows(stmt);
        if (updatedMeta == 0) {
                Lctx(ctx, "No rows updated");
        } else if (updatedMeta > 1) {
                Lctx(ctx, "%llu tokens invalidated", updatedMeta);
        }
        Lctx(ctx, "User token invalidated");

        var query2 = "INSERT INTO logins (user_id, token) VALUES (?, ?)";
        prep = mysql_stmt_prepare(stmt, query2, strlen(query2));
        if (prep) {
                Lctx(ctx, "Check the query, 🦆 %s", mysql_stmt_error(stmt));
                return ReturnCode(req, 500, "I'm kinda dead inside");
        }
        if (mysql_stmt_bind_param(stmt, bind2)) {
                Lctx(ctx, "Bind token failed %s", mysql_stmt_error(stmt));
                return ReturnCode(req, 500, "I'm kinda dead inside");
        }
        if (mysql_stmt_execute(stmt)) {
                Lctx(ctx, "DB execution failed %s", mysql_stmt_error(stmt));
                return ReturnCode(req, 500, "I'm kinda dead inside");
        }

        updatedMeta = mysql_stmt_affected_rows(stmt);
        if (updatedMeta == 0) {
                Lctx(ctx, "No rows updated %s", mysql_stmt_error(stmt));
        }
        Lctx(ctx, "Tokens inserted [%llu]", updatedMeta);

        // Add cookie, HTTPOnly, Secure, SameSite=Lax
        char tokenSTR[37];
        uuid_unparse(uuid, tokenSTR);
        __clean char *cookie;
        asprintf(&cookie, "token=%s; HttpOnly; SameSite=Lax", tokenSTR);
        evhttp_add_header(evhttp_request_get_output_headers(req), "Set-Cookie", cookie);

        return ReturnCodeBody(req, 200,
                              "<button id='listvideos' hx-post='/listVideos' hx-target='#videos'>List videos</button>"
                              "<div id='videos'"
                              "class='grid grid-cols-1 gap-4 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5'>"
                              "</div>");
}

void Router(struct evhttp_request *req, void *arg)
{
        struct requestContext ctx = {.req = req, .isRAM = false, .conn = arg};
        clock_gettime(CLOCK_REALTIME, &ctx.time);
        evhttp_connection_get_peer(evhttp_request_get_connection(req), &ctx.ip, &ctx.port);

        static struct funcRoutes routes[] = {{.route = "/login", .func = Login, .method = EVHTTP_REQ_POST},
                                             {.route = "/", .func = Index, .method = EVHTTP_REQ_GET},
                                             {.route = "/Index", .func = Index, .method = EVHTTP_REQ_GET},
                                             {.route = "/favicon.ico", .func = generic_request_handler, .method = EVHTTP_REQ_GET},
                                             {.route = "/Error", .func = Error, .method = EVHTTP_REQ_GET},
                                             {.route = "/counter", .func = Counter, .method = EVHTTP_REQ_GET},
                                             {.route = "/requestToken", .func = RequestToken, .method = EVHTTP_REQ_GET},
                                             {.route = "/mp4file", .func = sendMp4Pipe, .method = EVHTTP_REQ_POST},
                                             {.route = "/listVideos", .func = listVideos, .method = EVHTTP_REQ_POST},
                                             {.route = "/newVideo", .func = genVideoPipe, .method = EVHTTP_REQ_GET}};

        var uri = evhttp_request_get_uri(req);
        if (uri == nullptr) {
                Lctx(&ctx, "URI is NULL");
                return ReturnCode(req, 400, "URI is NULL");
        }

        __clean char *uriClean = NULL;
        var urlpath = evhttp_uri_get_path(evhttp_request_get_evhttp_uri(req));
        if (urlpath == nullptr) {
                Lctx(&ctx, "URL Path is NULL");
                return ReturnCode(req, 400, "URL Path is NULL");
        }
        assert(asprintf(&uriClean, "%s", urlpath) > 0);

        var query = evhttp_uri_get_query(evhttp_request_get_evhttp_uri(req));
        if (query) {
                __clean char *tmp = uriClean;
                assert(asprintf(&uriClean, "%s queries:%s", tmp, query) > 0);
        } else {
                __clean char *tmp = uriClean;
                assert(asprintf(&uriClean, "%s queries:None", tmp) > 0);
        }

        bool found = false;
        var method = evhttp_request_get_command(req);
        // Insensitively compare the uri with the routes
        for (uint i = 0; i < sizeof(routes) / sizeof(struct funcRoutes); i++) {
                Ld("Comparing %s with %s", urlpath, routes[i].route);
                if (method == routes[i].method && strcasecmp(urlpath, routes[i].route) == 0) {
                        Ld("Route found: %s, method: %s", routes[i].route, getMethod(routes[i].method));
                        routes[i].func(req, &ctx);
                        found = true;
                        break;
                }
        }

        struct timespec end;
        clock_gettime(CLOCK_REALTIME, &end);
        if (!ctx.isRAM) // Means no return was sent from the url
                Lctx(&ctx, "URI: %s Method: %s : %s [%.5fms]", urlpath, getMethod(evhttp_request_get_command(req)), found ? "Found" : "Not found",
                     (end.tv_sec - ctx.time.tv_sec) * 1000 + (end.tv_nsec - ctx.time.tv_nsec) / 1000000.0);

        found ?: ReturnCode(req, 404, "Not found");
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
// Both null-terminated
b_i32 FieldIntQuery(char *query, char *field)
{
        char *fieldStart = strstr(query, field);
        if (fieldStart == NULL)
                return (b_i32){.err = true, .val = 0};

        fieldStart += strlen(field) + 1; // Worst case scenario, the field is the last one
        Ld("FieldStart: %s", fieldStart);
        return (b_i32){.err = false, .val = atoi(fieldStart)};
}

b_str FieldStrQuery(char *query, char *field)
{
        char *fieldStart = strstr(query, field);
        if (fieldStart == NULL)
                return (b_str){.err = true, .val = NULL};

        fieldStart += strlen(field) + 1; // Worst case scenario, the field is the last one
        char *end;
        for (end = fieldStart; *end != '&' && *end != '\0'; end++)
                ;
        if (end == fieldStart)
                return (b_str){.err = true, .val = NULL};

        Ld("%s: %.*s", field, (int)(end - fieldStart), fieldStart);
        return (b_str){.err = false, .val = fieldStart, .len = end - fieldStart};
}

void RequestToken(struct evhttp_request *req, void *arg)
{
        var adminUser = "admin";
        var adminPass = "admin";
        struct requestContext *ctx = arg;
        var reply = evbuffer_new();
        Lctx(ctx, "Requesting token");
        var querytmp = evhttp_uri_get_query(evhttp_request_get_evhttp_uri(req));
        {
                if (querytmp == nullptr) {
                        Lctx(ctx, "No query");
                        goto errorbye;
                }
        }
        var user = FieldStrQuery(querytmp, "user");
        var pass = FieldStrQuery(querytmp, "pass");
        if (user.err || pass.err)
                goto errorbye;
        if (strncmp(user.val, adminUser, user.len) != 0 || strncmp(pass.val, adminPass, pass.len) != 0) {
                Lctx(ctx, "Invalid user = %.*s pass = %.*s", user.len, user.val, pass.len, pass.val);
                goto errorbye;
        } else {
                var fakeToken = "{\"token\":\"1234567890\"}";
                evbuffer_add(reply, fakeToken, strlen(fakeToken));
                evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/json");
        }
errorbye:;
        evhttp_send_reply(req, 401, "Not valid, pal", reply);
        evbuffer_free(reply);
}
