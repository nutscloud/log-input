#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "parse_auditlog.h"
#define AUDITLOG_BUFSIZE 1024000

char auditlog_buf[AUDITLOG_BUFSIZE];
struct list_head auditlog_list;

static void set_chunk(char **start, struct chunk *chunk, char end_flag)
{
	int len = 0;

	chunk->str = *start;
	while (**start != end_flag) {
		len++;
		(*start)++;
	}

	chunk->len = len;
}

static char *parse_part_a(char *start, struct session_info *si, char *part)
{
	char *str;
	int n = 1;

	for (str = start; 1; str++) {
		if (*str == '-' && *(str + 1) == '-' && *(str + 10) == '-' && *(str + 12) == '-' && *(str + 13) == '-') {
			*part = *(str + 11);
			return str + 15;
		}

		if (*str == '[') {
			str++;
			set_chunk(&str, &si->happentime, ']');
			n++;
			continue;
		}

		if (*str == ']') {
			*str = '\0';
			continue;
		}

		if (*str != ' ') {
			switch (n) {
				case 2:
					set_chunk(&str, &si->unique_id, ' ');
					n++;
					break;
				case 3:
					set_chunk(&str, &si->sip, ' ');
					n++;
					break;
				case 4:
					set_chunk(&str, &si->sport, ' ');
					n++;
					break;
				case 5:
					set_chunk(&str, &si->dip, ' ');
					n++; break;
				case 6:
					set_chunk(&str, &si->dport, '\n');
					n++;
					break;
			}
		}
	}
}

static char *parse_part_b(char *start, struct session_info *si, char *part)
{

	char *str;
	int chunk_index = 1;

	si->request_header.str = start;
	si->request_header.len = -1;
	for (str = start; 1; str++) {
		if (*str == '-' && *(str + 1) == '-' && *(str + 10) == '-' && *(str + 12) == '-' && *(str + 13) == '-') {
			*part = *(str + 11);
			*(str - 1) = '\0';
			return str + 15;
		}

		if (*str != ' ') {
			switch (chunk_index) {
				case 1:
					set_chunk(&str, &si->method, ' ');
					chunk_index++;
					break;
				case 2:
					set_chunk(&str, &si->url, ' ');
					chunk_index++;
					break;
			}

			if (*str == 'H' && *(str + 1) == 'o' && *(str + 2) == 's' && *(str + 3) == 't') {
				str += 6;
				set_chunk(&str, &si->hostname, '\n');
			}

			if (*str == 'U' && *(str + 1) == 's' && *(str + 2) == 'e' && *(str + 3) == 'r'
					&& *(str + 4) == '-' && *(str + 5) == 'A' && *(str + 6) == 'g'
					&& *(str + 7) == 'e' && *(str + 8) == 'n' && *(str + 9) == 't') {
				str += 12;
				set_chunk(&str, &si->user_agent, '\n');
			}
		}
	}
}

static char *parse_part_c(char *start, struct session_info *si, char *part)
{
	char *str;

	si->request_body.str = start;
	si->request_body.len = -1;
	for (str = start; 1; str++) {
		if (*str == '-' && *(str + 1) == '-' && *(str + 10) == '-' && *(str + 12) == '-' && *(str + 13) == '-') {
			*part = *(str + 11);
			*(str - 1) = '\0';
			return str + 15;
		}
	}
}

static char *parse_part_e(char *start, struct session_info *si, char *part)
{
	char *str;

	si->response_body.str = start;
	si->response_body.len = -1;
	for (str = start; 1; str++) {
		if (*str == '-' && *(str + 1) == '-' && *(str + 10) == '-' && *(str + 12) == '-' && *(str + 13) == '-') {
			*part = *(str + 11);
			*(str - 1) = '\0';
			return str + 15;
		}
	}
}

static char *parse_part_f(char *start, struct session_info *si, char *part)
{
	char *str;

	si->response_header.str = start;
	si->response_header.len = -1;
	for (str = start; 1; str++) {
		if (*str == '-' && *(str + 1) == '-' && *(str + 10) == '-' && *(str + 12) == '-' && *(str + 13) == '-') {
			*part = *(str + 11);
			*(str - 1) = '\0';
			return str + 15;
		}

		if (*str == 'H' && *(str + 1) == 'T' && *(str + 2) == 'T' && *(str + 3) == 'P' && *(str + 4) == '/') {
			str += 9;
			set_chunk(&str, &si->response_code, ' ');
		}
	}
}

/*\
 *parse triggered rule 
 *@start: start point to the start of contents of part h
 *@si   : struct session_info
 *@part : return tht index of next part through part
 */
static char *parse_part_h(char *start, struct session_info *si, char *part)
{
	char *str;
	struct alarm_info *ai = NULL;
	//int set_action_id_val = 0;

	for (str = start; 1; str++) {
		if (*str == '-' && *(str + 1) == '-' && *(str + 10) == '-' && *(str + 12) == '-' && *(str + 13) == '-') {
			*part = *(str + 11);
			return str + 15;
		}

		if (*str == 'M' && *(str + 1) == 'e' && *(str + 2) == 's' && *(str + 3) == 's' && *(str + 4) == 'a' 
				&& *(str + 5) == 'g' && *(str + 6) == 'e' && *(str + 7) == ':' ) {
			if ((ai = calloc(1, sizeof(struct alarm_info))) == NULL) {
				logg("[parse_part_h]failed to alloc struct alarm_info"); ////////
				/* to next line */
				while (1) {
					if (*str == '\n')
						break;
					str++;
				}
				continue;
			}

			list_add_tail(&ai->list, &auditlog_list);
			ai->sinfo = si;
			si->count++;

			str += 9;

			if (strncmp(str, "Warning", strlen("Warning")) == 0) {
				ai->action_id.str = "2"; 		/* pass */
				ai->action_id.len = -1;
				str += strlen("Warning");
			} else if (strncmp(str, "Access denied with redirection",
						strlen("Access denied with redirection")) == 0) {
				ai->action_id.str = "4"; 		/* redirection*/
				ai->action_id.len = -1;
				str += strlen("Access denied with redirection");
			} else if (strncmp(str, "Access denied with connection close",
						strlen("Access denied with connection close")) == 0) {
				ai->action_id.str = "5"; 		/* drop */
				ai->action_id.len = -1;
				str += strlen("Access denied with connection close");
			} else if (strncmp(str, "Access denied", strlen("Access denied")) == 0) {
				ai->action_id.str = "1"; 		/* deny */
				ai->action_id.len = -1;
				str += strlen("Access denied");
			} else if (strncmp(str, "Request body", strlen("Request body")) == 0) {
				ai->rule_id.str = "80020001";
				ai->rule_id.len = -1;
				ai->msg_id.str = "80020";
				ai->msg_id.len = -1;
				ai->severity_id.str = "2";
				ai->severity_id.len = -1;
				ai->tag_id.str = "8002";
				ai->tag_id.len = -1;
				str += strlen("Request body");
			} else if (strncmp(str, "Response body", strlen("Response body")) == 0) {
				ai->action_id.str = "1"; 		/* deny */
				ai->action_id.len = -1;
				ai->rule_id.str = "80030001";
				ai->rule_id.len = -1;
				ai->msg_id.str = "80030";
				ai->msg_id.len = -1;
				ai->tag_id.str = "8003";
				ai->tag_id.len = -1;
				ai->severity_id.str = "2";
				ai->severity_id.len = -1;
				str += strlen("Response body");
			} else if (strncmp(str, "Access allowed", strlen("Access allowed")) == 0) {
				ai->action_id.str = "3";
				ai->action_id.len = -1;
				str += strlen("Access allowed");
			} else {
				ai->action_id.str = "6";
				ai->action_id.len = -1;
			}

		} /*if (str == "Message")*/

		if (*str == '[') {
			str++;

			if (*str == 'i' && *(str + 1) == 'd' && *(str + 2) == ' ' && *(str + 3) == '"' ) {
				str += 4;
				
				set_chunk(&str, &ai->rule_id, '"');
			} else if (*str == 's' && *(str + 1) == 'e' && *(str + 2) == 'v' && *(str + 3) == 'e' 
					&& *(str + 4) == 'r' && *(str + 5) == 'i' && *(str + 6) == 't' 
					&& *(str + 7) == 'y' && *(str + 8) == ' ' && *(str + 9) == '"') {
				str += 10;

				set_chunk(&str, &ai->severity_id, '"');
			} else if (*str == 'd' && *(str + 1) == 'a' && *(str + 2) == 't' && *(str + 3) == 'a'
					&& *(str + 4) == ' ' && *(str + 5) == '"') {
				str += 6;

				set_chunk(&str, &ai->match, '"');
			} else if (*str == 'm' && *(str + 1) == 's' && *(str + 2) == 'g' && *(str + 3) == ' '
					&& *(str + 4) == '"') {
				str += 5;

				set_chunk(&str, &ai->msg_id, '"');
			} else if (*str == 't' && *(str + 1) == 'a' && *(str + 2) == 'g' && *(str + 3) == ' '
					&& *(str + 4) == '"') {
				str += 5;

				set_chunk(&str, &ai->tag_id, '"');
			}

		} /* if (*str == '[') */

	} /* for */
}


int parse_auditlog(char *fname)
{
	int fd;
	int n, count = 0;
	char *buf;
	char part = '\0';
	struct session_info *sinfo;
	
	if ((fd = open(fname, O_RDONLY)) == -1) {
		logg("[parse_auditlog]failed to open %s", fname);
		return -1;
	}

	buf = auditlog_buf;
	while ((n = read(fd, buf, AUDITLOG_BUFSIZE)) > 0) {
		buf += n;
		count += n;
	}

	if (n == -1 || auditlog_buf[count - 4] != 'Z') {
		logg("[parse_auditlog]failed to read %s", fname);
		return -1;
	}

	if ((sinfo = calloc(1, sizeof(struct session_info))) == NULL) {
		logg("[parse_auditlog]failed to alloc");
		return -1;
	}

	buf = auditlog_buf;

	/* for example: --11e8642c-F-- */
	if (*buf == '-' && *(buf + 1) == '-' && *(buf + 10) == '-' && *(buf + 12) == '-' && *(buf + 13) == '-') {
		part = *(buf + 11);
		buf += 15;
	}
	while (buf < auditlog_buf + count) {

		switch (part) {
			case 'A': buf = parse_part_a(buf, sinfo, &part); break;
			case 'B': buf = parse_part_b(buf, sinfo, &part); break;
			case 'C': buf = parse_part_c(buf, sinfo, &part); break;
			case 'E': buf = parse_part_e(buf, sinfo, &part); break;
			case 'F': buf = parse_part_f(buf, sinfo, &part); break;
			case 'H': buf = parse_part_h(buf, sinfo, &part); break;
			case 'Z': break;
		}

		if (buf == NULL) {
			return -1;
		}
	}

	return 0;
}
