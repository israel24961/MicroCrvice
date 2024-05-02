#include "database.h"
#include <0_GlobalIncludes.h>
#include <uuid/uuid.h>

MYSQL *DatabaseInit(char *host, char *user, char *pass, char *db, u32 port)
{
        var conn = mysql_init(NULL);
        if (conn == NULL) {
                Le("mysql_init() failed");
                return nullptr;
        }
        if (mysql_real_connect(conn, host, user, pass, db, port, NULL, 0) == NULL) {
                Le("mysql_real_connect() failed");
                return nullptr;
        }
        L("Connected to MySQL server %s:%d", host, port);
        // Test query
        if (mysql_query(conn, "SELECT 1") != 0) {
                Le("mysql_query() failed");
                return nullptr;
        }
        var e = mysql_field_count(conn);
        if (e != 1) {
                Le("mysql_field_count() failed");
                return nullptr;
        }
        var res = mysql_store_result(conn);
        if (res == NULL) {
                Le("mysql_store_result() failed");
                return nullptr;
        }
        var row = mysql_fetch_row(res);
        if (row == NULL) {
                Le("mysql_fetch_row() failed");
                return nullptr;
        }
        L("MySQL server version: %s", row[0]);
        if (strcmp(row[0], "1") != 0) {
                Le("mysql_fetch_row() failed");
                return nullptr;
        }
        mysql_free_result(res);

        L("MySQL server is up and running");

        return conn;
}

// Don't pass null
char *MYSQL_TIME_toString(MYSQL_TIME *time)
{
        // I could actually append the fmt as a macro to the evbuffer_add_printf call, but fuck it
        var fmt = "%04d-%02d-%02d"
                  "%02d:%02d:%02d";
        char *str;
        asprintf(&str, fmt, time->year, time->month, time->day, time->hour, time->minute, time->second);
        return str;
}

struct db_users *dbUserDataFromToken(MYSQL *conn, u_char *token)
{
        struct db_users *user = calloc(1, sizeof(struct db_users));
        if (!(conn && token)) {
                return user;
        }
        var query = "SELECT u.id, u.user, u.pass, u.email, u.created_at, u.updated_at"
                    " FROM users u WHERE id = (SELECT user_id FROM logins WHERE token = ?)";
        __cleanSTMT var stmt = mysql_stmt_init(conn);
        if (!stmt) {
                Le("mysql_stmt_init() failed");
                return user;
        }
        if (mysql_stmt_prepare(stmt, query, strlen(query))) {
                Le("mysql_stmt_prepare() failed");
                return user;
        }
        MYSQL_BIND bind[1] = {{.buffer_type = MYSQL_TYPE_BLOB, .buffer = token, .buffer_length = sizeof(uuid_t), .is_null = 0, .length = 0}};

        bool isNulls = 0;
        ulong length = 0;
        MYSQL_BIND resultBind[] = {
            {.buffer_type = MYSQL_TYPE_LONG, .buffer = &user->id, .is_null = &isNulls, .length = &length},
            {.buffer_type = MYSQL_TYPE_STRING, .buffer = user->username, .buffer_length = kDB_LOGINMAX_USER, .is_null = &isNulls, .length = &length},
            {.buffer_type = MYSQL_TYPE_STRING, .buffer = user->password, .buffer_length = kDB_LOGINMAX_PASS, .is_null = &isNulls, .length = &length},
            {.buffer_type = MYSQL_TYPE_STRING, .buffer = user->email, .buffer_length = kDB_LOGINMAX_EMAIL, .is_null = &isNulls, .length = &length},
            {.buffer_type = MYSQL_TYPE_DATETIME, .buffer = &user->created_at, .is_null = &isNulls, .length = &length},
            {.buffer_type = MYSQL_TYPE_DATETIME, .buffer = &user->updated_at, .is_null = &isNulls, .length = &length},
        };

        if (mysql_stmt_bind_param(stmt, bind) || mysql_stmt_execute(stmt)) {
                Le("mysql_stmt_bind_param() failed");
                return user;
        }
        if (mysql_stmt_bind_result(stmt, resultBind)) {
                Le("mysql_stmt_bind_result() failed");
                return user;
        }

        if (mysql_stmt_store_result(stmt) || mysql_stmt_fetch(stmt)) {
                Le(" bind/store/fetch failed");
                return user;
        }
        __clean var created = MYSQL_TIME_toString(&user->created_at);
        __clean var updated = MYSQL_TIME_toString(&user->updated_at);

        Ld("User: %d %s %s %s %s %s", user->id, user->username, user->password, user->email, created, updated);

        mysql_stmt_free_result(stmt);
        return user;
}

void dbClean(MYSQL **ptr) { mysql_close(*ptr); }
void dbstmtClean(MYSQL_STMT **ptr) { mysql_stmt_close(*ptr); }
void dbmetaClean(MYSQL_RES **ptr) { mysql_free_result(*ptr); }

// Token should be uuit_t, not a string
struct LoginsList *dbLoginsDataByUserFromToken(MYSQL *conn, u_char *token, int page, int limit)
{

        struct LoginsList *resp = nullptr;
        __cleanSTMT var stmt = mysql_stmt_init(conn);
        if (!stmt) {
                Le("mysql_stmt_init() failed");
                return nullptr;
        }
        var query = "SELECT l.id, l.created_at, l.invalidated_at, l.token, l.duration"
                    " FROM logins l WHERE user_id = (SELECT user_id FROM logins WHERE token = ? and invalidated_at IS NULL)"
                    "ORDER BY l.id desc LIMIT ?, ?";
        if (mysql_stmt_prepare(stmt, query, strlen(query))) {
                Le("mysql_stmt_prepare() failed %s : query(%s)", mysql_stmt_error(stmt), query);
                return nullptr;
        }
        var toSkip = (page - 1) * limit;
        MYSQL_BIND inputParams[] = {{.buffer_type = MYSQL_TYPE_BLOB, .buffer = token, .buffer_length = sizeof(uuid_t), .is_null = 0, .length = 0},
                                    {.buffer_type = MYSQL_TYPE_LONG, .buffer = &toSkip, .is_null = 0, .length = 0},
                                    {.buffer_type = MYSQL_TYPE_LONG, .buffer = &limit, .is_null = 0, .length = 0}};
        if (mysql_stmt_bind_param(stmt, inputParams) || mysql_stmt_execute(stmt)) {
                Le("bind/exec failed %s", mysql_stmt_error(stmt));
                return nullptr;
        }

        bool isInvalidatedDateNull = 0;
        struct db_logins respRow;
        bool isNulls = 0;
        ulong length = 0;
        MYSQL_BIND resultBind[] = {
            {.buffer_type = MYSQL_TYPE_LONG, .buffer = &respRow.id, .is_null = &isNulls, .length = &length},
            {.buffer_type = MYSQL_TYPE_DATETIME, .buffer = &respRow.created_at, .is_null = &isNulls, .length = &length},
            {.buffer_type = MYSQL_TYPE_DATETIME, .buffer = &respRow.invalidated_at, .is_null = &isInvalidatedDateNull, .length = &length},
            {.buffer_type = MYSQL_TYPE_BLOB, .buffer = respRow.token, .buffer_length = sizeof(uuid_t), .is_null = &isNulls, .length = &length},
            {.buffer_type = MYSQL_TYPE_TINY, .buffer = &respRow.duration, .is_null = &isNulls, .length = &length}};
        if (mysql_stmt_bind_result(stmt, resultBind) || mysql_stmt_store_result(stmt)) {
                Le("bind/store failed %s", mysql_stmt_error(stmt));
                return nullptr;
        }

        __cleanMETA var res = mysql_stmt_result_metadata(stmt);
        if (!res)
                return nullptr;

        // Number of results
        var numRow = mysql_stmt_num_rows(stmt);
        resp = calloc(1, sizeof(struct LoginsList) + numRow * sizeof(struct db_logins));
        resp->len = numRow;
        int i = 0;
        while (mysql_stmt_fetch(stmt) == 0) {
                resp->logins[i] = respRow;
                if (isInvalidatedDateNull) {
                        resp->logins[i].invalidated_at = (MYSQL_TIME){0};
                }
                i++;
        }
        mysql_stmt_free_result(stmt);
        return resp;
}

// @param token should be uuit_t, not a string
bool db_InvalidToken(MYSQL *conn, u_char *token)
{
        __cleanSTMT var stmt = mysql_stmt_init(conn);
        if (!stmt) {
                Le("mysql_stmt_init() failed");
                return false;
        }
        var query = "UPDATE logins SET invalidated_at = NOW() WHERE token = ?";
        if (mysql_stmt_prepare(stmt, query, strlen(query))) {
                Le("mysql_stmt_prepare() failed %s : query(%s)", mysql_stmt_error(stmt), query);
                return false;
        }
        MYSQL_BIND inputParams[] = {{.buffer_type = MYSQL_TYPE_BLOB, .buffer = token, .buffer_length = sizeof(uuid_t), .is_null = 0, .length = 0}};
        if (mysql_stmt_bind_param(stmt, inputParams) || mysql_stmt_execute(stmt)) {
                Le("bind/exec failed %s", mysql_stmt_error(stmt));
                return false;
        }
        if (mysql_stmt_store_result(stmt)) {
                Le("No rows affected");
                return false;
        }
        var affected = mysql_stmt_affected_rows(stmt);
        Ld("Invalidated %d tokens", affected);
        mysql_stmt_free_result(stmt);
        return true;
}
