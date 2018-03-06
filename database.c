#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>

#include "database.h"
#include "log.h"
#include "list.h"

int efd;

#if 0
void insert_db_list(struct mysql_poll *entry, struct mysql_info *mi)
{
	if (mi->list == NULL) {
		mi->list = entry;
	}

	entry->next = mi->list;
	mi->list = entry;
}
#endif


void init_db_connection(struct mysql_info *mi)
{
	struct mysql_poll *poll;

	if ((poll = calloc(1, sizeof(struct mysql_poll))) == NULL) {
		logg("[init_db_connection]failed to alloc struct mysql_poll");
	}

	insert_list(mi->list, poll);

	if ((mi->list->my = mysql_init(NULL)) == NULL) {
		logg("[init_db_connection]mysql_init error");
	}

	if (mysql_real_connect(mi->list->my, mi->host, mi->user, mi->passwd,
				mi->name, 0, mi->u_socket, 0) == NULL) {
		logg("[init_db_connection]mysql_real_connect:%s", mysql_error(mi->list->my));

		mysql_close(mi->list->my);
	}
}

void db_close(MYSQL *m)
{
	if (m)
		mysql_close(m);
}

int reconnect(struct mysql_info *mi)
{
	MYSQL *m = mi->list->my;

	if (m) {
		mysql_close(m);
		m = NULL;
	}

	if ((m = mysql_init(NULL)) == NULL) {
		logg("[reconnect]mysql_init error");
		return -1;
	}

	if (mysql_real_connect(m, mi->host, mi->user, mi->passwd,
				mi->name, 0, mi->u_socket, 0) == NULL) {
		logg("[reconnect]mysql_real_connect:%s", mysql_error(mi->list->my));
		mysql_close(mi->list->my);
		m = NULL;
		return -1;
	}

	return 1;
}

void deal_db_return(struct mysql_info *minfo)
{
	MYSQL *my;

	my = minfo->list->my;

	if (mysql_read_query_result(my) != 0) {
		logg("[deal_db_return]mysql_query:%s", mysql_error(my));

		if (mysql_errno(my) == CR_SERVER_GONE_ERROR) {
			mysql_close(my);
			my = NULL;
		}
	}

	minfo->list->used = 0;
}

int db_insert(struct push *p)
{
	char escaped[SEND_BUF_SIZE * 2 + 1];
	struct mysql_poll *mp;
	struct epoll_event ev;
	MYSQL *my;

	mp = p->m_info->list;
	while (mp) {
		if (mp->used == 0)
			break;

		mp = mp->next;
	}

	if (mp == NULL) {
	
		if ((mp = calloc(1, sizeof(struct mysql_poll))) == NULL) {
			logg("[init_db_connection]failed to alloc struct mysql_poll");
		}

		insert_list(p->m_info->list, mp);

		if ((mp->my = mysql_init(NULL)) == NULL) {
			logg("[init_db_connection]mysql_init error");
		}

		if (mysql_real_connect(mp->my, 
					p->m_info->host,
					p->m_info->user,
					p->m_info->passwd,
					p->m_info->name, 0, 
					p->m_info->u_socket, 0) == NULL) {
			logg("[init_db_connection]mysql_real_connect:%s", mysql_error(mp->my));

			mysql_close(mp->my);
		}
	}

	my = mp->my;

	mysql_real_escape_string(my, escaped, p->mysql_buf.buf, SEND_BUF_SIZE);
	if (my != NULL) {
		mysql_send_query(my, escaped, strlen(escaped));

		ev.events = EPOLLIN|EPOLLOUT|EPOLLET|EPOLLONESHOT;
		ev.data.ptr = p->m_info;
		epoll_ctl(efd, EPOLL_CTL_ADD, my->net.fd, &ev);

		mp->used = 1;
	}

	return 1;
}
