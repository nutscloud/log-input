#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

#include "log.h"
#include "parse_conf_file.h"
#include "list.h"
#include "database.h"
#include "syslog.h"
#include "rule.h"
#define CONFIG_BUF_SIZE 4096

struct key_val *kv_list;
struct inot_file *inot_list;
struct push *push_list;

int stack_size; 
char config_buf[CONFIG_BUF_SIZE]; 		/* the contents of config file arre filled in this buf */

#if 0
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
#endif


/*\
 * get a string block that start at @start and end by @end,
 * the @change replace the @end.
 * */
char *get_entry(char **start, char end, char change)
{
	char *str;

	while(isspace(**start)) {
		/*if (**pos == '\n')
			return NULL;*/
		(*start)++;
	}

	str = *start;
	while (**start != end) {
		(*start)++;
	}

	**start = change;
	(*start)++;
	return str;
}

/*\
 * this function parse key:value part in the config file and
 * return pointer that point to starting of the next part
 * @start pointer that point to starting of the this part
 * @part return index of next part
 */
char *cfg_parse_kv(char *start, char *part)
{
	char *str;
	struct key_val *kv;

	for (str = start; 1;) {
		while(isspace(*str))
			str++;

		if (*str == '-' && *(str + 1) == '-' && *(str + 9) == '-' && *(str + 11) == '-' && *(str + 12) == '-') {
			*part = *(str + 10);
			return str + 14;
		}

		if ((kv = calloc(1, sizeof(struct key_val))) == NULL) {
			logg("[cfg_parse_kw]failed to alloc struct key_val");
			exit(1);
		}

		insert_list(kv_list, kv);
		kv->key = get_entry(&str, ':', '\0');
		kv->val = get_entry(&str, '\n', '\0');
	}
}

/*\
 *
 * @start pointer that point to starting of the this part
 * @part return index of next part
 */
char *cfg_parse_inotify(char *start, char *part)
{
	char *str, *type;
	struct inot_file *inot;

	for (str = start; 1;) {
		while(isspace(*str))
			str++;

		if (*str == '-' && *(str + 1) == '-' && *(str + 9) == '-' && *(str + 11) == '-' && *(str + 12) == '-') {
			*part = *(str + 10);
			return str + 14;
		}

		if ((inot = calloc(1, sizeof(struct inot_file))) == NULL) {
			logg("failed to alloc inot_file");
			exit(1);
		}

		insert_list(inot_list, inot);
		inot->path = get_entry(&str, ' ', '\0');

		/* get file mode type */
		type = get_entry(&str, ' ', '\0');
		if (strcmp(type, "write") == 0)
			inot->mtype = WRITE;
		else if (strcmp(type, "append") == 0)
			inot->mtype = APPEND;

		/* get file event type */
		type = get_entry(&str, '\n', '\0');
		if (strcmp(type, "auditlog") == 0)
			inot->etype == AUDITLOG;
		else if (strcmp(type, "cc") == 0)
			inot->etype == CC;
	}
}


#if 0
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
#endif
struct tree_node *cfg_parse_rule(char **line, struct action *act)
{
	struct tree_node *tn, *root;
	char *pos, *end;
	int i;

	end = strchr(*line, '\n');
	*end = ' ';

	for (; *line < end;) {
		while (isspace(**line)) {
			(*line)++;
			continue;
		}

		if (**line == '!') {
			tn = calloc(1, sizeof(struct tree_node));
			tn->type = OPERATOR;
			tn->name.oname = NOT;
			push(tn);

			(*line)++;
		} else if (**line == '(') {
			tn = calloc(1, sizeof(struct tree_node));
			tn->type = PARETHESE;
			push(tn);

			(*line)++;
		} else if (**line == '&' && *(++(*line)) == '&') {
			tn = calloc(1, sizeof(struct tree_node));
			tn->type = OPERATOR;
			tn->name.oname = AND;
			push(tn);

			(*line)++;
		} else if (**line == '|' && *(++(*line)) == '|') {
			tn = calloc(1, sizeof(struct tree_node));
			tn->type = OPERATOR;
			tn->name.oname = OR;
			push(tn);

			(*line)++;
		} else if (**line == ')') {
			gen_rule_tree();

			(*line)++;
		} else {
			tn = calloc(1, sizeof(struct tree_node));
			
			pos = get_entry(line, ' ', '\0');
			for (i = 0; map[i].name != NULL; i++) {
				if (strcmp(pos, map[i].name) == 0) {
					tn->name.ename = map[i].entry;
					break;
				}
			}

			pos = get_entry(line, ' ', '\0');
			for (i = 0;opet_map[i].name != NULL; i++) {
				if (strcmp(pos, opet_map[i].name) == 0) {
					tn->op = opet_map[i].opet;
					break;
				}
			}

			pos = get_entry(line, ' ', '\0');
			if (tn->op == REGEX)
				regcomp(&tn->operand.reg, pos, REG_EXTENDED);
			else if (tn->op == STREQ)
				tn->operand.str = pos;
			else
				tn->operand.inte = atoi(pos);

			push(tn);
		}
	}

	root = gen_rule_tree();
	return root;
}

static void cfg_parse_send_contents(char **line, struct action *act)
{
	char *end, *entry;
	int i;

	end = strchr(*line, '\n');
	*end = ' ';

	while (*line < end) {

		entry = get_entry(line, ' ', '\0');

		for (i = 0; map[i].name; i++) {
			if (strcmp(entry, map[i].name) == 0) {
				act->send_contents[act->num] = map[i].entry;
				act->num++;
				break;
			}
		}
	}
}

static char *cfg_parse_push(char *start, char *part)
{
	char *str;
	struct push *push;
	struct mysql_info *minfo;
	struct action *act;

	if ((push = calloc(1, sizeof(struct push))) == NULL) {
		logg("failed to alloc push");
		return NULL;
	}

	push->first = time(NULL);
	push->mysql_buf.last = push->mysql_buf.buf;
	push->mysql_buf.end = &push->mysql_buf.buf[SEND_BUF_SIZE - 1];

	push->syslg_buf.last = push->syslg_buf.buf;
	push->syslg_buf.end = &push->syslg_buf.buf[SEND_BUF_SIZE - 1];

	insert_list(push_list, push);

	for (str = start; 1;) {
		while(isspace(*str))
			str++;

		if (*str == '-' && *(str + 1) == '-' && *(str + 9) == '-' && *(str + 11) == '-' && *(str + 12) == '-') {
			*part = *(str + 10);
			return str + 14;
		}

		if (strncmp(str, "remote_ip:", strlen("remote_ip:")) == 0) {
			str += strlen("remote_ip:");
			
			push->remote_ip = get_entry(&str, '\n', '\0');

		} else if (strncmp(str, "mysql_info:", strlen("mysql_info:")) == 0) {
			str += strlen("mysql_info:");
			
			if ((minfo = calloc(1, sizeof(struct mysql_info))) == NULL) {
				logg("[cfg_parse_push] failed to alloc struct mysql_info");
				exit(1);
			}

			push->m_info = minfo;

			if (strcmp((minfo->host = get_entry(&str,' ', '\0')), "null") == 0)
				minfo->host = NULL;
			if (strcmp((minfo->user = get_entry(&str,' ', '\0')), "null") == 0)
				minfo->user = NULL;
			if (strcmp((minfo->passwd = get_entry(&str,' ', '\0')), "null") == 0)
				minfo->passwd = NULL;
			if (strcmp((minfo->name = get_entry(&str,' ', '\0')), "null") == 0)
				minfo->name = NULL;
			minfo->port = atoi(get_entry(&str,' ', '\0'));

			if (strcmp((minfo->u_socket = get_entry(&str,'\n', '\0')), "null") == 0)
				minfo->u_socket = NULL;

		} else if (strncmp(str, "syslog_info:", strlen("syslog_info:")) == 0) {
			str += strlen("syslog_info:");
		} else if (strncmp(str, "action", strlen("action")) == 0) {
			str += strlen("action");

			if ((act = calloc(1, sizeof(struct action))) == NULL) {
			
			}

			insert_list(push->act_list, act);
			act->push = push;

			for (; 1; str++)  {
				if (*str == '}')
					break;

				if (strncmp(str, "rule:", strlen("rule:")) == 0) {
					str += strlen("rule:");
					cfg_parse_rule(&str, act);
				} else if (strncmp(str, "sendi_contents:", strlen("send_contents:")) == 0) {
					str += strlen("sendi_contents:");
					cfg_parse_send_contents(&str, act);
				} else if (strncmp(str, "send_type:", strlen("send_type:")) == 0) {
					str += strlen("send_type:");
					str = get_entry(&str, '\n', '\0');
					if (strcmp(str, "mysql") == 0)
						act->s_type = S_MYSQL;

					else if (strcmp(str, "syslog") == 0)
						act->s_type = SYSLOG;
				}
			}

		}
	}
}

int parse_config_file(const char *fname)
{
	int fd;
	char *buf;
	//struct key_val *kv, *head;
	int n, count = 0;
	char part;

	if ((fd = open(fname, O_RDONLY)) == -1) {
		logg("failed to open config file %s\n", fname);
		exit(1);
	}

	buf = config_buf;
	while((n = read(fd, buf, CONFIG_BUF_SIZE)) > 0) {
		buf += n;
		count += n;
	}

	if (n == -1 || config_buf[count - 4] != 'Z') {
		logg("[parse_config]failed to read %s", fname);
		return -1;
	}
	
	buf = config_buf;
	if (*buf == '-' && *(buf + 1) == '-' && *(buf + 9) == '-' && *(buf + 11) == '-' && *(buf + 12) == '-') {
		part = *(buf + 10);
		buf += 14;
	}
	while (buf < config_buf + count) {
		
		switch (part) {
			case 'A': buf = cfg_parse_kv(buf, &part); break;
			case 'B': buf = cfg_parse_push(buf, &part); break;
			case 'C': buf = cfg_parse_inotify(buf, &part); break;
			case 'Z': break;
		}
	}

	if (buf == NULL)
		return -1;
	return 0;
}
