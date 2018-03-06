#ifndef DATABASE_H
#define DATABASE_H

#include <mysql/mysql.h>
#include <mysql/errmsg.h>
#include "parse_conf_file.h"
struct mysql_poll {
	MYSQL *my;
	char used;

	struct mysql_poll *next;
};

struct mysql_info {
	enum events_type etype;
	char *host;
	char *user;
	char *passwd;
	char *name;
	int port;
	char *u_socket;

	struct mysql_poll *list;
};
extern int efd;
void insert_db_list(struct mysql_poll *entry, struct mysql_info *mi);
void init_db_connection(struct mysql_info *mi);
void db_close(MYSQL *m);
int reconnect(struct mysql_info *mi);
void deal_db_return(struct mysql_info *mi);
int db_insert(struct push *p);

#endif
