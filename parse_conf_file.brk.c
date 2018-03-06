#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>

#include "log.h"
#include "parse_conf_file.h"
#include "list.h"
#include "database.h"
#include "syslog.h"
#include "rule.h"
#define LINE_SIZE 1024

struct key_val *kv_list;
struct inot_file *inot_list;
struct push *push_list;

int stack_size;
/*
 *ship space or comment in a line
 */
char *skip_space_or_comment (char *str)
{
	while (isspace(*str)) {
		if (*str == '\n')
			return NULL;
		str++;
	}

	if (*str == '#')
		return NULL;
	return str;
}

char *get_entry(char *start, int dup)
{
	static char *pos;
	static int end = 0;
	char *str;

	if (start != NULL)
		pos = start;

	if (end == 1)
		return NULL;

	pos++;
	while(isspace(*pos)) {
		if (*pos == '\n')
			return NULL;
		pos++;
	}
	str = pos;
	if ((pos = strchr(str, ' ')) == NULL) {
		pos = strchr(str, '\n');
		end = 1;
	}
	pos = '\0';

	if (dup)
		return strdup(str);
	return str;
}
/*
 *
 */
static int cfg_parse_inotify(FILE *fp)
{
	char line[LINE_SIZE];
	char *pos, *str;
	struct inot_file *inot;

	while (fgets(line, LINE_SIZE, fp)) {

		if (strchr(line, '}'))
			return 1;

		if ((str = skip_space_or_comment(line)) == NULL)
			continue;

		if ((pos = strchr(str, ' ')) == NULL) {
			logg("error inotify line");
			continue;
		}
		
		*pos = '\0';
		if ((inot = calloc(1, sizeof(struct inot_file))) == NULL) {
			logg("failed to alloc inot_file");
			continue;
		}
		inot->path = strdup(str);

		str = pos;
		if (strcasestr(str, "write"))
			inot->type = WRITE;
		else if (strcasestr(str, "append"))
			inot->type = APPEND;

		insert_list(inot_list, inot);
	}
}

struct mysql_info *cfg_parse_mysql_info(char *line)
{
	struct mysql_info *m_info;
	char *pos, *str;

	if ((pos = strchr(line, ':')) == NULL) {
		logg("mysql_info line error");
		return NULL;
	}

	if ((m_info = calloc(1, sizeof(struct mysql_info))) == NULL) {
		logg("failed to alloc mysql_info");
		return NULL;
	}

	m_info->host = get_entry(pos, 1);
	m_info->user = get_entry(NULL, 1);
	m_info->passwd = get_entry(NULL, 1);
	m_info->name = get_entry(NULL, 1);
	m_info->port = atoi(get_entry(NULL, 0));
	m_info->u_socket = get_entry(NULL, 1);

	return m_info;
}

struct syslog_info *cfg_parse_syslog_info(char *line)
{
	struct syslog_info *s_info;
	char *pos, *str;

	if ((pos = strchr(line, ':')) == NULL) {
		logg("syslog_info line error");
		return NULL;
	}

	if ((s_info = calloc(1, sizeof(struct syslog_info))) == NULL) {
		logg("failed to alloc syslog_info");
		return NULL;
	}

	s_info->port = atoi(get_entry(pos, 0));
	
	str = get_entry(NULL, 0);
	if ((str == NULL) == 0)
		s_info->prot = NUL;
	else if (strcmp(str, "tcp") == 0)
		s_info->prot = TCP;
	else if (strcmp(str, "udp") == 0)
		s_info->prot = UDP;

	return s_info;
}

struct tree_node *cfg_parse_rule(char *line)
{
	struct tree_node *tn, root;
	char *pos, *str;

	if ((pos = strchr(line, ':')) == NULL) {
		logg("rule line error");
		return NULL;
	}

	str = get_entry(pos, 0);
	if (*str == '!' || *str == '(') {
		
	}
	while (get_entry(NULL, 0)) {}
}

struct push_node *cfg_parse_push_node(FILE *fp)
{
	struct tree_node *tn = NULL;
	struct push_node *pn = NULL;
	char *pos, *str;
	char line[LINE_SIZE];

	if ((pn = calloc(1, sizeof(struct push_node))) == NULL) {
		logg("failed to alloc push_node");
	}

	while (fgets(line, LINE_SIZE, fp)) {
		if (strchr(line, '}'))
			return pn;

		if ((str = skip_space_or_comment(line)) == NULL)
			continue;

		if (strcasestr(str, "send")) {
			
		} else if (strcasestr(str, "rule")) {
			pn->rule = cfg_parse_rule(str);
		}
	}
}
static int cfg_parse_push(FILE *fp)
{
	char line[LINE_SIZE];
	char *str, *pos, *tmp;
	struct push *push;

	if ((push = calloc(1, sizeof(struct push))) == NULL) {
		logg("failed to alloc push");
		return 0;
	}

	while (fgets(line, LINE_SIZE, fp))
	{
		if (strchr(line, '}'))
			return 1;

		if ((str = skip_space_or_comment(line)) == NULL)
			continue;

		if (strcasestr(str, "remote_ip")){
			
		} else if (strcasestr(str, "mysql_info")) {
			push->m_info = cfg_parse_mysql_info(str);
		} else if (strcasestr(str, "syslog_info")) {
			push->s_info = cfg_parse_syslog_info(str);
		} else if (strcasestr(str, "push")) {
			push->list = cfg_parse_push_node(fp);
		}
	}
}

struct conf_file *config_file_load(char *fname)
{
	FILE *fp;
	char line[LINE_SIZE];
	char *str, *pos, *end, *tmp;
	struct key_val *kv, *head;

	if ((fp = fopen(fname, "r")) == NULL) {
		logg("failed to open config file %s\n", fname);
		exit(1);
	}

	while(fgets(line, LINE_SIZE, fp)) {
		
		if ((str = skip_space_or_comment(line)) == NULL)
			continue;

		if ((pos = strchr(str, ':')) == NULL) {
			if ((pos = strchr(str, '{')) != NULL) {
				if (strcasestr(str, "push")) {
					cfg_parse_push(fp);
					continue;
				}

				if (strcasestr(str, "inotify")) {
					cfg_parse_inotify(fp);
					continue;
				}
			}
		}
		
		if ((kv = calloc(1, sizeof(struct key_val))) == NULL) {
			logg("failed to alloc conf_file");
			exit(1);
		}

		tmp = pos;
		while (isspace(*(--tmp)));
		*(++tmp) = '\0';
		kv->key = strdup(str);

		while (isspace(*pos))
			pos++;
		str = pos;
		pos = pos + strlen(str);
		while (isspace(*(--pos)));
		*(++pos) = '\0';
		kv->val = strdup(str);

		insert_list(kv_list, kv);
	}

	fclose(fp);
}
