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
        char *username;
        char *password;
        char *email;
        MYSQL_TIME* created_at;
        MYSQL_TIME* updated_at;
};
 
struct db_logins {
        int id;
        int user_id;
        u_char token[16];
};

struct db_users *db_users_new();

MYSQL *DatabaseInit(char *host, char *user, char *pass, char *db, u32 port);
