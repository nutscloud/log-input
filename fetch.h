#ifndef FETCH_H
#define FETCH_H

#include "type.h"
#include "list.h"

enum log_entry {
	AUDIT_ACT_ID,
	AUDIT_RULE_ID,
	AUDIT_MSG_ID,
	AUDIT_SEVE_ID,
	AUDIT_TAG_ID,
	AUDIT_MATCH,
	AUDIT_SIP,
	AUDIT_DIP,
	AUDIT_SPORT,
	AUDIT_DPORT,
	AUDIT_UNI_ID,
	AUDIT_HPTIME,
	AUDIT_RES_CODE,
	AUDIT_METHOD,
	AUDIT_URL,
	AUDIT_HOSTNAME,
	AUDIT_USER_AGENT,
	AUDIT_REQ_BODY,
	AUDIT_REQ_HDR,
	AUDIT_RES_HDR,
	AUDIT_RES_BODY,
	LOG_ENTRY_MAX,
	//NUL = -1
};

struct log_entry_map{
	char *name;
	char *mtname; 					/* mysql table name */
	char *mcname; 					/* mysql column name */
	enum log_entry entry;
	struct chunk *(*fetch)(void *entry);
};

extern struct log_entry_map map[];
#if 0
struct chunk *fetch_audit_act_id(struct list_head *entry);
struct chunk *fetch_audit_rule_id(struct list_head *entry);
struct chunk *fetch_audit_msg_id(struct list_head *entry);
struct chunk *fetch_audit_seve_id(struct list_head *entry);
struct chunk *fetch_audit_tag_id(struct list_head *entry);
struct chunk *fetch_audit_match(struct list_head *entry);
struct chunk *fetch_audit_sip(struct list_head *entry);
struct chunk *fetch_audit_dip(struct list_head *entry);
struct chunk *fetch_audit_sport(struct list_head *entry);
struct chunk *fetch_audit_dport(struct list_head *entry);
struct chunk *fetch_audit_uni_id(struct list_head *entry);
struct chunk *fetch_audit_hptime(struct list_head *entry);
struct chunk *fetch_audit_res_code(struct list_head *entry);
struct chunk *fetch_audit_method(struct list_head *entry);
struct chunk *fetch_audit_url(struct list_head *entry);
struct chunk *fetch_audit_hostname(struct list_head *entry);
struct chunk *fetch_audit_user_agent(struct list_head *entry);
struct chunk *fetch_audit_req_body(struct list_head *entry);
struct chunk *fetch_audit_req_hdr(struct list_head *entry);
struct chunk *fetch_audit_res_hdr(struct list_head *entry);
struct chunk *fetch_audit_res_body(struct list_head *entry);
#endif
struct chunk *fetch_audit_act_id(void *entry);
struct chunk *fetch_audit_rule_id(void *entry);
struct chunk *fetch_audit_msg_id(void *entry);
struct chunk *fetch_audit_seve_id(void *entry);
struct chunk *fetch_audit_tag_id(void *entry);
struct chunk *fetch_audit_match(void *entry);
struct chunk *fetch_audit_sip(void *entry);
struct chunk *fetch_audit_dip(void *entry);
struct chunk *fetch_audit_sport(void *entry);
struct chunk *fetch_audit_dport(void *entry);
struct chunk *fetch_audit_uni_id(void *entry);
struct chunk *fetch_audit_hptime(void *entry);
struct chunk *fetch_audit_res_code(void *entry);
struct chunk *fetch_audit_method(void *entry);
struct chunk *fetch_audit_url(void *entry);
struct chunk *fetch_audit_hostname(void *entry);
struct chunk *fetch_audit_user_agent(void *entry);
struct chunk *fetch_audit_req_body(void *entry);
struct chunk *fetch_audit_req_hdr(void *entry);
struct chunk *fetch_audit_res_hdr(void *entry);
struct chunk *fetch_audit_res_body(void *entry);
#endif
