#include "database.h"

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
