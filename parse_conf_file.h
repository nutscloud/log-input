#ifndef PARSE_CONF_FILE_H
#define PARSE_CONF_FILE_H
#include "list.h"
#include "fetch.h"
#define SEND_BUF_SIZE 1024000

enum mode {WRITE, APPEND};
enum send_type {S_MYSQL, SYSLOG};

struct key_val {
	char *key;
	char *val;

	struct key_val *next;
};

struct inot_file {
	enum events_type etype;
	enum mode mtype;
	off_t offset;
	char *path;

	struct inot_file *next;
};

struct action {
	struct tree_node *rule;
	enum log_entry send_contents[LOG_ENTRY_MAX];
	int num; 					/* the number of send contents */

	enum send_type s_type;

	struct push *push;
	struct action *next;
};

struct buf {
	char buf[SEND_BUF_SIZE];
	char *last;
	char *end;

	int num;
};

struct push {
	struct action *act_list;
	char *remote_ip;
	
	struct mysql_info *m_info;
	struct syslog_info *s_info;
	time_t first;
	struct buf mysql_buf;
	struct buf syslg_buf;

	struct push *next;
};

extern int stack_size;
extern struct key_val *kv_list;
extern struct inot_file *inot_list;
extern struct push *push_list;

int parse_config_file(const char *fname);
#endif
