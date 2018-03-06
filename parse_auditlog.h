#ifndef PARSE_AUDIT_LOG_H
#define PARSE_AUDIT_LOG_H

#include "list.h"
#include "type.h"
struct session_info
{
	struct chunk sip;
	struct chunk dip;
	struct chunk sport;
	struct chunk dport;
	struct chunk unique_id;
	struct chunk happentime;
	struct chunk response_code;
	struct chunk method;
	struct chunk url;
	struct chunk hostname;
	struct chunk user_agent;
	struct chunk request_header;
	struct chunk request_body;
	struct chunk response_header;
	struct chunk response_body;

	int count; 		//reference counter
};

struct alarm_info {
	enum events_type type;
	struct chunk action_id;
	struct chunk rule_id;
	struct chunk msg_id;
	struct chunk severity_id;
	struct chunk tag_id;
	struct chunk match;

	//char *mtname; 			/* mysql table name */
	struct session_info *sinfo;
	struct list_head list;
};

extern struct list_head auditlog_list;
extern char auditlog_buf[];
int parse_auditlog(char *);

#endif
