#include <errno.h>
#include <fcntl.h>
//#include <mysql/mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "daemon.h"
#include "log.h"
#include "parse_auditlog.h"
#include "parse_conf_file.h"
#include "rule.h"
#include "type.h"

#include "database.h"
#define READ_BUF_SIZE 8192

int process_audit_file(char *, char *);
int process_cc_file(char *, char *);

int send_size;
int send_wait;
//extern int efd;
struct datatype types[TYPE_MAX] = {
	[AUDITLOG] = { .name = "auditlog",
		.line_f = process_audit_file, },
	[CC]   = { .name = "cc",
		.line_f = process_cc_file, },
};

static int process_lines(char *buffer, int n, struct inot_file *i)
{
	char    *lf, *line, *end;
	int     t;
	
	line = buffer;
	end = buffer + n;
	
	while (1) {
		if (line >= end) {
			line = end;
			break;
		}
		
		lf = memchr(line, '\n', end - line);
		
		if (!lf)
			break;
		*lf = '\0';
		//logg("%s\n", line);
		t = i->etype;
		
		if (t >= 0 && t < TYPE_MAX &&
				types[t].line_f) {
			types[t].line_f(line, lf);
		}
		
		line = lf + 1;
	}
	
	return (line - buffer);
}
int tail_file(struct inot_file *inot)
{
	struct  stat st;
	int     rt, fd;
	static  char buffer[READ_BUF_SIZE];
	
	rt = stat(inot->path, &st);
	
	if (rt < 0)
		goto err;
	
	if ((inot->mtype == APPEND && st.st_size < inot->offset) || (st.st_size == 0)) {
		/* file truncated */
		inot->offset = st.st_size;
		goto err;
	}

	fd = open(inot->path, O_RDONLY);
	if (fd < 0) {
		logg("open %s [%d]\n", inot->path, errno);
		goto err;
	}

	if ((lseek(fd, inot->offset, SEEK_SET) < 0)) {
		logg("lseek %s %d [%d]\n", inot->path, inot->offset, errno);
		goto err_after_fd;
	}
	
	while(1) {
		size_t  n, t;
		
		n = read(fd, buffer, READ_BUF_SIZE);
		
		if (n < 0) {
			logg("read %s [%d]\n", inot->path, errno);
			goto err_after_fd;
		}
		
		if (n == 0)
			 break;
		
		t = process_lines(buffer, n, inot);
		
		if (t == n) {
			inot->offset += n;
		} else if (t == 0) {
			if (n < READ_BUF_SIZE) { /* half line in file*/
				break;
			} else { /* line too long */
				inot->offset += n;
			}
		} else if (t < n) { /* half line in buffer */
			inot->offset += t;
			if ((lseek(fd, inot->offset, SEEK_SET) < 0)) {
				logg("lseek %s %d [%d]\n", inot->path, inot->offset, errno);
				goto err_after_fd;
			}
		}
		
		if (inot->offset >= st.st_size)
			break;
	}
	
	close(fd);
	
	return 0;

err_after_fd:
	close(fd);
err:
	return -1;
}

int fill_mysql_buf(struct action *act, void *log)
{
	struct chunk *chunk;
	//struct push *push;
	char *buf, *last, *end, *tablename, *str;
	int i, n;
	enum events_type type;

	buf = act->push->mysql_buf.buf;
	last = act->push->mysql_buf.last;
	end = act->push->mysql_buf.end;

	memcpy(&type, log, sizeof(enum events_type));
	if (type == AUDITLOG) {
		tablename = "alarms";
	} else if (type == CC) {
		tablename = "cc_alarms";
	}else {
		tablename = "";
	}

	n = sprintf(last, "INSERT INFO %s (", tablename);
	last += n;

	for (i = 0; i < act->num; i++) {
		str = map[act->send_contents[i]].mcname;

		n = sprintf(last, "%s%s", str, (i + 1 >= act->num) ? ")" : ",");
		last += n;
	}

	n = sprintf(last, " VALUES (");
	last += n;

	for (i = 0; i < act->num; i++) {
		chunk = map[act->send_contents[i]].fetch(log);

		if (chunk->len == -1) {
			n = sprintf(last, "%s%s", chunk->str, (i + 1 >= act->num) ? ")" : ",");
			last += n;
		} else {
			n = snprintf(last, chunk->len + 1, "%s%s", chunk->str, (i + 1 >= act->num) ? ")" : ",");
			last += n;
		}
	}

	return 1;
}
void auditlog_traverse_push()
{
	struct alarm_info *ainfo, *next;
	struct push *push;
	struct action *act;
	int ret;
	//struct chunk *entry;

	list_for_each_entry_safe(ainfo, next, &auditlog_list, list) {
		push = push_list;

		while (push != NULL){

			act = push->act_list;
			while (act != NULL) {
			
				if ((ret = traverse_rule_tree(ainfo, act->rule)) == 1) {
					if (act->s_type == S_MYSQL) {
						fill_mysql_buf(act, ainfo);
					} else if (act->s_type == SYSLOG) {
					}
				}
				
				act = act->next;
			}
			push = push->next;
		}

		ainfo->sinfo->count--;

		if (ainfo->sinfo->count == 0)
			free(ainfo->sinfo);
		free(ainfo);
	}
}
int process_cc_file(char *line, char *end)
{
	return 1;
}
int process_audit_file(char *line, char *end)
{
	char *fname = NULL;

	/* find the audit file name from index file*/
	while (line < end) {
		if (*line == ' ' && *(line + 1) == '\\') {

			fname = line + 1;
			while(line < end) {
				if (*line == ' ') {
					*line = '\0';
					break;
				}

				line++;
			}
		}

		line++;
	}

	if (fname == NULL)
		return 0;

	parse_auditlog(fname);
	auditlog_traverse_push();
	return 1;
}

int main(int argc, char **argv)
{
	const char * config_file;
	char c;
	int ifd;
	struct inot_file *inot;

	config_file = "/waf/config/misc/push_log.conf";
	while ((c = getopt(argc, argv, "f:")) != -1) {
		switch (c) {
			case 'f': config_file = strdup(optarg); break;
			default: usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage();

	if (strcmp(argv[0], "start") == 0) {
		logg("<push_log start>\n");
		start();
	} else if (strcmp(argv[0], "stop") == 0) {
		logg("<push_log stop>\n");
		stop();
		exit(0);
	} else if (strcmp(argv[0], "restart") == 0) {
		logg("<push_log restart>\n");
		restart();
	} else {
		usage();
	}

	if (parse_config_file(config_file) == -1) {
		logg("can`t open config file: %s\n", config_file);
		exit(1);
	}

	ifd = inotify_init();
	efd = epoll_create(10);
	
	inot = inot_list;
	while (inot) {
		struct epoll_event ev;

		inotify_add_watch(ifd, inot->path, IN_ALL_EVENTS);
		
		ev.events = EPOLLIN|EPOLLOUT|EPOLLET;
		ev.data.ptr = inot;
		epoll_ctl(efd, EPOLL_CTL_ADD, ifd, &ev);

		inot = inot->next;
	}

	while (1) {
		int n;
		int i;
		enum events_type etype;
		struct epoll_event events[10];
		struct mysql_info *minfo;
		//char *fname;
		struct push *p;

		n = epoll_wait(efd, events, 10, 0);

		for (i = 0; i < n; i++) {

			memcpy(&etype, events[i].data.ptr, sizeof(enum events_type));

			switch (etype) {
				case AUDITLOG:
					/*inot = (struct inot_file *)events[i].data.ptr;

					while (fname = parse_auditlog_index_file(inot->fd)) {
						
						if (strlen(fname) != INDEX_FILENAME_LENGTH) {
							logg("invalid auditlog file name %s:", fname);
							continue;
						}

						deal_auditlog(fname);
					}

					break;*/
				case CC:
					inot = (struct inot_file *)events[i].data.ptr;
					tail_file(inot);
					break;
				case E_MYSQL:
					minfo = (struct mysql_info *)events[i].data.ptr;

					deal_db_return(minfo);
					break;
				case TYPE_MAX:
					break;
			}
		}

		p = push_list;
		while (p) {
			if (p->mysql_buf.num > send_size || p->first + send_wait < time(NULL))
				db_insert(p);

			p = p->next;
		}
	}/* while (1) main loop*/
}
