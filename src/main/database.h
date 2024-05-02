#pragma once
#include <0_GlobalIncludes.h>
// Mariadb includes
#include <mysql/errmsg.h>
#include <mysql/mariadb_version.h>
#include <mysql/mysql.h>
#include <mysql/mysqld_error.h>

#define kDB_LOGINMAX_USER 63
#define kDB_LOGINMAX_PASS 63
#define kDB_LOGINMAX_EMAIL 127

struct db_users {
        int id;
        char username[kDB_LOGINMAX_USER];
        char password[kDB_LOGINMAX_PASS];
        char email[kDB_LOGINMAX_EMAIL];
        MYSQL_TIME created_at;
        MYSQL_TIME updated_at;
};

struct db_logins {
        int id;
        MYSQL_TIME created_at;
        MYSQL_TIME invalidated_at;
        u_char token[16];
        u_char duration;
};

//
// Struct for query filters/sorts/pagination/etc
struct QSort {
        char *field;
        char *order;
};
struct QFilter {
        char *field;
        char *value;
        char *op;
};
struct QLimit {
        u32 offset;
        u32 limit;
};

struct db_users *db_users_new();

MYSQL *DatabaseInit(char *host, char *user, char *pass, char *db, u32 port);

// If the token is valid, returns the user data associated with the token
// otherwise, returns a user with the fields set to 0
__attr(malloc) struct db_users *dbUserDataFromToken(MYSQL *conn, u_char *token);

struct LoginsList {
        u32 len;
        struct db_logins logins[];
};
// If the token is valid, returns the logins list associated with the user
// the last item is a zeroed db_logins struct(0s in all fields)
__attr(malloc) struct LoginsList *dbLoginsDataByUserFromToken(MYSQL *conn, u_char *token, int page, int limit);

bool db_InvalidToken(MYSQL *conn, u_char *token);

void dbClean(MYSQL **ptr);
void dbstmtClean(MYSQL_STMT **ptr);
void dbmetaClean(MYSQL_RES **ptr);
#define __cleanSTMT __attribute__((cleanup(dbstmtClean)))
#define __cleanMETA __attribute__((cleanup(dbmetaClean)))

__attr(malloc) char *MYSQL_TIME_toString(MYSQL_TIME *time);

