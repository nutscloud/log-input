#include <stdio.h>
#include <string.h>

#include "fetch.h"
#include "parse_auditlog.h"

struct log_entry_map map[LOG_ENTRY_MAX + 1] = {
	[AUDIT_ACT_ID] = {.name = "audit_act_id",
		.mtname = "alarms",	
		.mcname = "action_id",
		.entry = AUDIT_ACT_ID, 
		.fetch = fetch_audit_act_id},
	[AUDIT_RULE_ID] = {.name = "audit_rule_id", 
		.mtname = "alarms",
		.mcname = "rule_id",
		.entry = AUDIT_RULE_ID, 
		.fetch = fetch_audit_rule_id},
	[AUDIT_MSG_ID] = {.name = "audit_msg_id", 
		.mtname = "alarms",
		.mcname = "msg_id",	
		.entry = AUDIT_MSG_ID, 
		.fetch = fetch_audit_msg_id},
	[AUDIT_SEVE_ID] = {.name = "audit_seve_id", 
		.mtname = "alarms",
		.mcname = "severity_id", 
		.entry = AUDIT_SEVE_ID, 
		.fetch = fetch_audit_seve_id},
	[AUDIT_TAG_ID] = {.name = "audit_tag_id", 
		.mtname = "alarms",
		.mcname = "tag_id", 
		.entry = AUDIT_TAG_ID, 
		.fetch = fetch_audit_tag_id},
	[AUDIT_MATCH] = {.name = "audit_match", 
		.mtname = "alarms",
		.mcname = "match", 
		.entry = AUDIT_MATCH, 
		.fetch = fetch_audit_match},
	[AUDIT_SIP] = {.name = "audit_sip", 
		.mtname = "alarms",
		.mcname = "sip", 
		.entry = AUDIT_SIP, 
		.fetch = fetch_audit_sip},
	[AUDIT_DIP] = {.name = "audit_dip", 
		.mtname = "alarms",
		.mcname = "dip",
		.entry = AUDIT_DIP, 
		.fetch = fetch_audit_dip},
	[AUDIT_SPORT] = {.name = "audit_sport", 
		.mtname = "alarms",
		.mcname = "sport",
		.entry = AUDIT_SPORT, 
		.fetch = fetch_audit_sport},
	[AUDIT_DPORT] = {.name = "audit_dport", 
		.mtname = "alarms",
		.mcname = "dport",
		.entry = AUDIT_DPORT, 
		.fetch = fetch_audit_dport},
	[AUDIT_UNI_ID] = {.name = "audit_uni_id", 
		.mtname = "alarms",
		.mcname = "unique_id",
		.entry = AUDIT_UNI_ID, 
		.fetch = fetch_audit_uni_id},
	[AUDIT_HPTIME] = {.name = "audit_hptime", 
		.mtname = "alarms",
		.mcname = "happentime",
		.entry = AUDIT_HPTIME, 
		.fetch = fetch_audit_hptime},
	[AUDIT_RES_CODE] = {.name = "audit_res_code", 
		.mtname = "alarms",
		.mcname = "response_code", 
		.entry = AUDIT_RES_CODE, 
		.fetch = fetch_audit_res_code},
	[AUDIT_METHOD] = {.name = "audit_method", 
		.mtname = "",
		.mcname = "", 
		.entry = AUDIT_METHOD, 
		.fetch = fetch_audit_method},
	[AUDIT_URL] = {.name = "audit_url", 
		.mcname = "url", 
		.entry = AUDIT_URL, 
		.fetch = fetch_audit_url},
	[AUDIT_HOSTNAME] = {.name = "audit_hostname", 
		.mcname = "hostname", 
		.entry = AUDIT_HOSTNAME, 
		.fetch = fetch_audit_hostname},
	[AUDIT_USER_AGENT] = {.name = "audit_user_agent", 
		.mcname = "user_agent", 
		.entry = AUDIT_USER_AGENT, 
		.fetch = fetch_audit_user_agent},
	[AUDIT_REQ_BODY] = {.name = "audit_req_body", 
		.mcname = "post", 
		.entry = AUDIT_REQ_BODY, 
		.fetch = fetch_audit_req_body},
	[AUDIT_REQ_HDR] = {.name = "audit_req_hdr", 
		.mcname = "request_header", 
		.entry = AUDIT_REQ_HDR, 
		.fetch = fetch_audit_req_hdr},
	[AUDIT_RES_HDR] = {.name = "audit_res_hdr", 
		.mcname = "response_header", 
		.entry = AUDIT_RES_HDR, 
		.fetch = fetch_audit_res_hdr},
	[AUDIT_RES_BODY] = {.name = "audit_res_body", 
		.mcname = "response_body", 
		.entry = AUDIT_RES_BODY, 
		.fetch = fetch_audit_res_body},
	[LOG_ENTRY_MAX] = {.name = NULL, 
		.mcname = "", 
		//.entry = NUL, 
		.fetch = NULL},
};

struct chunk *fetch_audit_act_id(void *entry)
{
	struct alarm_info *ainfo;

	ainfo = (struct alarm_info *)entry;
	//ainfo = list_entry(entry, typeof(*ainfo), list);

	return &ainfo->action_id;
}
struct chunk *fetch_audit_rule_id(void *entry)
{
	struct alarm_info *ainfo;

	ainfo = (struct alarm_info *)entry;
	//ainfo = list_entry(entry, typeof(*ainfo), list);

	return &ainfo->rule_id;
}
struct chunk *fetch_audit_msg_id(void *entry)
{
	struct alarm_info *ainfo;

	ainfo = (struct alarm_info *)entry;
	//ainfo = list_entry(entry, typeof(*ainfo), list);

	return &ainfo->msg_id;
}
struct chunk *fetch_audit_seve_id(void *entry)
{
	struct alarm_info *ainfo;

	ainfo = (struct alarm_info *)entry;
	//ainfo = list_entry(entry, typeof(*ainfo), list);

	return &ainfo->severity_id;
}
struct chunk *fetch_audit_tag_id(void *entry)
{
	struct alarm_info *ainfo;

	ainfo = (struct alarm_info *)entry;
	//ainfo = list_entry(entry, typeof(*ainfo), list);

	return &ainfo->tag_id;
}
struct chunk *fetch_audit_match(void *entry)
{
	struct alarm_info *ainfo;

	ainfo = (struct alarm_info *)entry;
	//ainfo = list_entry(entry, typeof(*ainfo), list);

	return &ainfo->match;
}
struct chunk *fetch_audit_sip(void *entry)
{
	struct alarm_info *ainfo;

	ainfo = (struct alarm_info *)entry;
	//ainfo = list_entry(entry, typeof(*ainfo), list);

	return &ainfo->sinfo->sip;
}
struct chunk *fetch_audit_dip(void *entry)
{
	struct alarm_info *ainfo;

	ainfo = (struct alarm_info *)entry;
	//ainfo = list_entry(entry, typeof(*ainfo), list);

	return &ainfo->sinfo->dip;
}
struct chunk *fetch_audit_sport(void *entry)
{
	struct alarm_info *ainfo;

	ainfo = (struct alarm_info *)entry;
	//ainfo = list_entry(entry, typeof(*ainfo), list);

	return &ainfo->sinfo->sport;
}
struct chunk *fetch_audit_dport(void *entry)
{
	struct alarm_info *ainfo;

	ainfo = (struct alarm_info *)entry;
	//ainfo = list_entry(entry, typeof(*ainfo), list);

	return &ainfo->sinfo->dport;
}
struct chunk *fetch_audit_uni_id(void *entry)
{
	struct alarm_info *ainfo;

	ainfo = (struct alarm_info *)entry;
	//ainfo = list_entry(entry, typeof(*ainfo), list);

	return &ainfo->sinfo->unique_id;
}
struct chunk *fetch_audit_hptime(void *entry)
{
	struct alarm_info *ainfo;

	ainfo = (struct alarm_info *)entry;
	//ainfo = list_entry(entry, typeof(*ainfo), list);

	return &ainfo->sinfo->happentime;
}
struct chunk *fetch_audit_res_code(void *entry)
{
	struct alarm_info *ainfo;

	ainfo = (struct alarm_info *)entry;
	//ainfo = list_entry(entry, typeof(*ainfo), list);

	return &ainfo->sinfo->response_code;
}
struct chunk *fetch_audit_method(void *entry)
{
	struct alarm_info *ainfo;

	ainfo = (struct alarm_info *)entry;
	//ainfo = list_entry(entry, typeof(*ainfo), list);

	return &ainfo->sinfo->method;
}
struct chunk *fetch_audit_url(void *entry)
{
	struct alarm_info *ainfo;

	ainfo = (struct alarm_info *)entry;
	//ainfo = list_entry(entry, typeof(*ainfo), list);

	return &ainfo->sinfo->url;
}
struct chunk *fetch_audit_hostname(void *entry)
{
	struct alarm_info *ainfo;

	ainfo = (struct alarm_info *)entry;
	//ainfo = list_entry(entry, typeof(*ainfo), list);

	return &ainfo->sinfo->hostname;
}
struct chunk *fetch_audit_user_agent(void *entry)
{
	struct alarm_info *ainfo;

	ainfo = (struct alarm_info *)entry;
	//ainfo = list_entry(entry, typeof(*ainfo), list);

	return &ainfo->sinfo->user_agent;
}
struct chunk *fetch_audit_req_body(void *entry)
{
	struct alarm_info *ainfo;

	ainfo = (struct alarm_info *)entry;
	//ainfo = list_entry(entry, typeof(*ainfo), list);

	return &ainfo->sinfo->request_body;
}
struct chunk *fetch_audit_req_hdr(void *entry)
{
	struct alarm_info *ainfo;

	ainfo = (struct alarm_info *)entry;
	//ainfo = list_entry(entry, typeof(*ainfo), list);

	return &ainfo->sinfo->request_header;
}
struct chunk *fetch_audit_res_hdr(void *entry)
{
	struct alarm_info *ainfo;

	ainfo = (struct alarm_info *)entry;
	//ainfo = list_entry(entry, typeof(*ainfo), list);

	return &ainfo->sinfo->response_header;
}
struct chunk *fetch_audit_res_body(void *entry)
{
	struct alarm_info *ainfo;

	ainfo = (struct alarm_info *)entry;
	//ainfo = list_entry(entry, typeof(*ainfo), list);

	return &ainfo->sinfo->response_body;
}
