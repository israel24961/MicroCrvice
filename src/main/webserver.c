#include "webserver.h"
#include <addresses.h>
#include <event2/http.h>
#include <time.h>

struct Routes {
        int indexLen;
        char *index;
        int error404Len;
        char *error404;
        int faviconLen;
        char *favicon;
        int mainLen;
        char *main;
        int loginLen;
        char *login;
        int listOfLoginsLen;
        char *listOfLogins;
};
char *HTTPMETHODS[] = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE", "CONNECT", "PATCH"};

void cleanEvBuf(struct evbuffer **ptr)
{
        evbuffer_free(*ptr);
        *ptr = NULL;
}
#define __cleanEVBUF __attribute__((cleanup(cleanEvBuf)))

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
#include <uuid/uuid.h>
struct requestContext {
        MYSQL *conn;
        char *ip;
        uint16_t port;
        struct evhttp_request *req;
        bool isRAM;           // Just in case some async stuff is needed
        struct timespec time; // For timing
        uuid_t token;
};

#define Lctx(ctx, fmt, ...) L("[%s][%d]" fmt, (ctx)->ip, (ctx)->port __VA_OPT__(, ) __VA_ARGS__)
#define Ldctx(ctx, fmt, ...) Ld("[%s][%d]" fmt, (ctx)->ip, (ctx)->port __VA_OPT__(, ) __VA_ARGS__)
#define LRctx(ctx, req, code, fmt, ...)                                                                                                              \
        (L("[%s][%d]" fmt, (ctx)->ip, (ctx)->port __VA_OPT__(, ) __VA_ARGS__), ReturnCode(req, code, fmt __VA_OPT__(, ) __VA_ARGS__))

/** Shouldn't test for token validity here **/
void Index(struct evhttp_request *req, void *arg)
{
        struct requestContext *ctx = arg;
        uuid_t defaultToken = {};
        return ReturnCodeBody(req, 200, root->index);
}
void Error(struct evhttp_request *req, void *arg)
{
        struct requestContext *ctx = arg;
        var reply = evbuffer_new();
        evbuffer_add(reply, root->error404, root->error404Len);
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
        // If / or /Index
        var uri = evhttp_request_get_uri(req);
        var uriHash = hash(uri, strlen(uri));
        __clean char *resp = NULL;
        // Sanity check
        var len = asprintf(&resp, "URI: %s URI Hash: %u", uri, uriHash);
        if (len < 0) {
                return ReturnCode(req, 501, "Oh nono, oh nono, oh nono nono nono");
        }

        if (uriHash == hash("/favicon.ico", strlen("/favicon.ico"))) {
                Lctx(ctx, "Favicon requested");
                var reply = evbuffer_new();
                evbuffer_add(reply, root->favicon, root->faviconLen);
                evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "image/x-icon");
                evhttp_send_reply(req, HTTP_OK, NULL, reply);
                evbuffer_free(reply);
        } else
                return (Lctx(ctx, "Not found %s", uri), ReturnCodeBody(req, 404, "Not found '%s'", uri));
        return;
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
        if (idVal.errMsg)
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

struct retUUID {
        uuid_t token;
        char *msg;
};

struct retUUID token_validate(b_str *token)
{
        struct retUUID ret = {.msg = NULL};
        if (token->len != 36)
                return (ret.msg = "Invalid token", ret);
        if (uuid_parse(token->val, ret.token))
                return (ret.msg = "Invalid token", ret);
        // Check if token is in the database (return date of token)
        return ret;
}
void LogoutPost(struct evhttp_request *req, void *arg)
{
        // Set cookie 'token' to empty
        struct requestContext *ctx = arg;
        __clean char *cookie;
        asprintf(&cookie, "token=delelted ; expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax");
        evhttp_add_header(evhttp_request_get_output_headers(req), "Set-Cookie", cookie);
        memset(ctx->token, 0, sizeof(ctx->token));
        return Main(req, ctx);
}

void LoginPost(struct evhttp_request *req, void *arg)
{
        struct requestContext *ctx = arg;
        var input = evhttp_request_get_input_buffer(req);
        if (input == nullptr) {
                L("Input buffer is NULL");
                return ReturnCode(req, 400, "I'm kinda dead inside");
        }
        var len = evbuffer_get_length(input);
        if (len == 0) {
                L("Input buffer is empty");
                return ReturnCode(req, 400, "I'm kinda dead inside");
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

        Lctx(ctx, "Login successful id: %d", id);
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

        memcpy(ctx->token, uuid, sizeof(uuid));

        return Main(req, ctx);
}

// Fucking date stuff
bool isTokenExpired(MYSQL_TIME *created, int durationMins)
{
        var now = time(NULL);
        var now_tm = localtime(&now);

        struct tm created_tm = {.tm_year = created->year - 1900,
                                .tm_mon = created->month - 1,
                                .tm_mday = created->day,
                                .tm_hour = created->hour,
                                .tm_min = created->minute,
                                .tm_sec = created->second,
                                .tm_isdst = now_tm->tm_isdst}; // Very fucking important
        var diff = difftime(mktime(now_tm), mktime(&created_tm));

        return diff > durationMins * 60 ? true : false;
}

/**
 * @brief ctx.token will be left untouched if the token is invalid
 *
 *  How the validation works is that if ctx.token is zeroed, the endpoints will not validate the access
 *  (even if they did, the user ID should never be visible to the client??), every user identification
 *  should be a query with of (select user_id from logins where token = ? and invalidated_at is null)
 *
 * @param ctx The request context
 * @param cookie The cookie string
 */
void LoadToken(struct requestContext *ctx, const char *cookie)
{
        var tokenbSTR = FieldStrQuery(cookie, "token");
        var token = token_validate(&tokenbSTR);
        if (token.msg) {
                Lctx(ctx, "Invalid token %s", token.msg);
                return;
        }
        // Check with the database
        var conn = ctx->conn;
        assert(conn);
        var query = "SELECT l.user_id, l.duration, l.token ,"
                    "l.created_at, "
                    "l.invalidated_at "
                    "FROM logins l WHERE l.token = ? and l.invalidated_at IS NULL";
        __cleanSTMT var stmt = mysql_stmt_init(conn);
        if (!stmt) {
                Lctx(ctx, "Stmt is NULL");
                return;
        }
        var prep = mysql_stmt_prepare(stmt, query, strlen(query));
        if (prep) {
                Lctx(ctx, "Check the query, dude 🦆 %s", mysql_stmt_error(stmt));
                return;
        }
        MYSQL_BIND bind[1] = {
            {.buffer_type = MYSQL_TYPE_BLOB, .buffer = token.token, .buffer_length = sizeof(token.token), .is_null = 0, .length = 0},

        };
        if (mysql_stmt_bind_param(stmt, bind)) {
                Lctx(ctx, "Bind failed");
                return;
        }
        if (mysql_stmt_execute(stmt)) {
                Lctx(ctx, "DB execution failed");
                return;
        }

        struct db_logins logins = {};
        char isNulls[5];
        ulong lengths[5];
        // clang-format off
        MYSQL_BIND result[] = {
            {.buffer_type = MYSQL_TYPE_LONG, .buffer = &logins.id, .is_null = isNulls, .length = lengths+0},
            {.buffer_type = MYSQL_TYPE_TINY, .buffer = &logins.duration, .is_null = isNulls+1, .length = lengths+4},
            {.buffer_type = MYSQL_TYPE_BLOB, .buffer = logins.token, .buffer_length = sizeof(logins.token), .is_null = isNulls+2, .length = lengths+3},
            {.buffer_type = MYSQL_TYPE_DATETIME, .buffer = &logins.created_at, .is_null = isNulls+3, .length =lengths+1},
            {.buffer_type = MYSQL_TYPE_DATETIME, .buffer = &logins.invalidated_at, .is_null = isNulls+4, .length =lengths+2}};
        // clang-format on

        if (mysql_stmt_bind_result(stmt, result) || mysql_stmt_store_result(stmt)) {
                Lctx(ctx, "Bind result or store failed");
                return;
        }
        struct db_logins validLogin = {};
        if (mysql_stmt_num_rows(stmt) == 0 || mysql_stmt_fetch(stmt) == MYSQL_NO_DATA) {
                Lctx(ctx, "No user has this token");
                return;
        }

        __clean var createdStr = MYSQL_TIME_toString(&logins.created_at);
        __clean var invalidatedStr = MYSQL_TIME_toString(&logins.invalidated_at);

        char uuidstr[37];
        uuid_unparse(logins.token, uuidstr);
        Ldctx(ctx, "Token: %s, User: %d, Duration: %d, Created: %s, Invalidated: %s", uuidstr, logins.id, logins.duration, createdStr,
              invalidatedStr);
        if (isTokenExpired(&logins.created_at, logins.duration)) {
                Lctx(ctx, "Token expired");
                db_InvalidToken(ctx->conn, logins.token);
                return;
        }

        if (logins.invalidated_at.year == 0) {
                Lctx(ctx, "Found a valid token: %s, comparing with the cookie %s, %s", uuidstr, tokenbSTR.val,
                     uuid_compare(logins.token, token.token) ? "Not Equal" : "Equal");
                validLogin = logins;
        }
        // Copy the token to the context (if it's invalid it will be a zeroed token)
        // Otherwiser, same value as the token
        // TODO: Check whether I should refresh the token before
        memcpy(ctx->token, validLogin.token, sizeof(validLogin.token));
        return;
}
// Doesn't need token
void LoginGet(struct evhttp_request *req, void *arg)
{
        // Redirect code to index
        struct requestContext *ctx = arg;
        // Location /
        evhttp_add_header(evhttp_request_get_output_headers(req), "Location", "/");
        evhttp_send_reply(req, 302, "OK", NULL);
        return;
}
void LoginsByToken(struct evhttp_request *req, void *arg)
{
        struct requestContext *ctx = arg;
        if(memcmp(ctx->token, (uuid_t){}, sizeof(uuid_t)) == 0){
            //refresh page
            return ReturnCode(req, 205, "/");
        }
        var loadMoreBtn = "<tr id='replaceMe'>"
                          "<td colspan='3'>"
                          "<button class='btn %s' hx-get='/loginsbytoken?page=%d'"
                          "     hx-target='#replaceMe' hx-swap='outerHTML' %s>"
                          "%s"
                          "</button>"
                          "</td>"
                          "</tr>";

        __cleanEVBUF var reply = evbuffer_new();
        var query = evhttp_uri_get_query(evhttp_request_get_evhttp_uri(req));

        var page = query ? FieldIntQuery(query, "page") : (b_i32){.errMsg = "No page query", .val = 1};
        page.val = page.val < 1 ? 1 : page.val;

        __clean var loggins = dbLoginsDataByUserFromToken(ctx->conn, ctx->token, page.val, 10);

        if (loggins == nullptr || loggins->len == 0) {
                evbuffer_add_printf(reply, loadMoreBtn, "btn-primary", page.val, "", "No more data");
                return evhttp_send_reply(req, HTTP_OK, "OK", reply);
        }

        var rowTemplate = "<tr><td>%d</td><td>%.36s</td><td>%s</td><td>%s</td></tr>";
        for (uint i = 0; i < loggins->len; i++) {
                var login = loggins->logins[i];
                char token[37];
                uuid_unparse(login.token, token);
                __clean var createdSTR = MYSQL_TIME_toString(&login.created_at);
                __clean var invalidatedSTR = MYSQL_TIME_toString(&login.invalidated_at);
                evbuffer_add_printf(reply, rowTemplate, login.id, token, createdSTR, invalidatedSTR);
        }
        evbuffer_add_printf(reply, loadMoreBtn, "btn-primary", ++page.val, "", "Load more");

        return evhttp_send_reply(req, HTTP_OK, "OK", reply);
}

void ListOfLoginsGet(struct evhttp_request *req, void *arg)
{
        struct requestContext *ctx = arg;
        // Check query in the get req
        var query = evhttp_uri_get_query(evhttp_request_get_evhttp_uri(req));
        if (query == nullptr)
                return ReturnCodeBody(req, 200, root->listOfLogins, "", 1, "", "Load data");
        var page = FieldIntQuery(query, "page");
        if (page.errMsg)
                return ReturnCodeBody(req, 200, root->listOfLogins, "", 1, "", "Load data");

        return ReturnCodeBody(req, 200, root->listOfLogins, ++page.val, "", "Load data");
}

void Main(struct evhttp_request *req, void *arg)
{
        struct requestContext *ctx = arg;

        var isZeroedToken = memcmp(ctx->token, (uuid_t){}, sizeof(uuid_t));
        if (!isZeroedToken) {
                return ReturnCodeBody(req, 200, root->login, "", "", "");
        }

        // Request user data
        struct db_users __clean *user = dbUserDataFromToken(ctx->conn, ctx->token);
        return ReturnCodeBody(req, 200, root->main, user->username, user->password, user->email);
}

void Router(struct evhttp_request *req, void *arg)
{
        struct requestContext ctx = {.req = req, .isRAM = false, .conn = arg};
        clock_gettime(CLOCK_REALTIME, &ctx.time);
        evhttp_connection_get_peer(evhttp_request_get_connection(req), &ctx.ip, &ctx.port);

        // TODO: CRINGE LIST turn it into a hashmap
        static struct funcRoutes routes[] = {{.route = "/login", .func = LoginGet, .method = EVHTTP_REQ_GET},
                                             {.route = "/login", .func = LoginPost, .method = EVHTTP_REQ_POST},
                                             {.route = "/listOfLogins", .func = ListOfLoginsGet, .method = EVHTTP_REQ_GET},
                                             {.route = "/logout", .func = LogoutPost, .method = EVHTTP_REQ_POST | EVHTTP_REQ_GET},
                                             {.route = "/loginsbytoken", .func = LoginsByToken, .method = EVHTTP_REQ_GET},

                                             {.route = "/", .func = Index, .method = EVHTTP_REQ_GET},
                                             {.route = "/Index", .func = Index, .method = EVHTTP_REQ_GET},
                                             {.route = "/favicon.ico", .func = generic_request_handler, .method = EVHTTP_REQ_GET},
                                             {.route = "/Error", .func = Error, .method = EVHTTP_REQ_GET},
                                             {.route = "/counter", .func = Counter, .method = EVHTTP_REQ_GET},
                                             {.route = "/requestToken", .func = RequestToken, .method = EVHTTP_REQ_GET},
                                             {.route = "/mp4file", .func = sendMp4Pipe, .method = EVHTTP_REQ_POST},
                                             {.route = "/listVideos", .func = listVideos, .method = EVHTTP_REQ_POST},
                                             {.route = "/newVideo", .func = genVideoPipe, .method = EVHTTP_REQ_GET},
                                             {.route = "/main", .func = Main, .method = EVHTTP_REQ_GET}};

        // Get cookies
        var cookie = evhttp_find_header(evhttp_request_get_input_headers(req), "Cookie");
        if (cookie)
                !cookie ?: LoadToken(&ctx, cookie);

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
                if ((method & routes[i].method) && strcasecmp(urlpath, routes[i].route) == 0) {
                        Ld("Route found: %s, method: %s", routes[i].route, getMethod(routes[i].method));
                        routes[i].func(req, &ctx);
                        found = true;
                        goto end;
                }
        }
        generic_request_handler(req, &ctx);
end:;
        struct timespec end;
        clock_gettime(CLOCK_REALTIME, &end);
        if (!ctx.isRAM) // Means no return was sent from the url
                Lctx(&ctx, "URI: %s Method: %s : %s [%.5fms]", urlpath, getMethod(evhttp_request_get_command(req)), found ? "Found" : "Not found",
                     (end.tv_sec - ctx.time.tv_sec) * 1000 + (end.tv_nsec - ctx.time.tv_nsec) / 1000000.0);

        found ?: ReturnCodeBody(req, 404, "Not found");
}

bool loadFile(char *path, char **dest, int *destLen, bool isBinary)
{
        var file = fopen(path, isBinary ? "rb" : "r");
        if (file == NULL) {
                Lf("Error opening %s", path);
                return false;
        }
        fseek(file, 0, SEEK_END);
        var size = *destLen = ftell(file);
        fseek(file, 0, SEEK_SET);
        *dest = malloc(size + 1);
        fread(*dest, 1, size, file);
        fclose(file);
        (*dest)[size] = 0;
        Ld("Loaded (%s) %s %d MB %d kB %d bytes", isBinary ? "binary" : "text", path, size / 1024 / 1024, size / 1024, size);
        return true;
}

// If no forth argument is given, it will be set to false
#define LLFF(filePath, root, memberName, ...) loadFile(filePath, &root->memberName, &root->memberName##Len, #__VA_ARGS__ == "true")
/** utils **/
bool loadFiles()
{
#define path "resources"
        root = malloc(sizeof(struct Routes));
        var err = LLFF(path "/index.html", root, index);
        err &= LLFF(path "/error.html", root, error404);
        err &= LLFF(path "/favicon.ico", root, favicon, true);
        err &= LLFF(path "/main.html", root, main);
        err &= LLFF(path "/login.html", root, login);
        err &= LLFF(path "/listOfLogins.html", root, listOfLogins);
        if (!err) {
                L("Failed to load files");
                return false;
        }
        return true;
}
// Both null-terminated
b_i32 FieldIntQuery(char *query, char *field)
{
        char *fieldStart = strstr(query, field);
        if (fieldStart == NULL)
                return (b_i32){.errMsg = "", .val = 0};

        fieldStart += strlen(field) + 1; // Worst case scenario, the field is the last one
        Ld("FieldStart: %s", fieldStart);
        return (b_i32){.errMsg = nullptr, .val = atoi(fieldStart)};
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
