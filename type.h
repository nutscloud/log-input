#ifndef TYPE_H
#define TYPE_H

enum events_type {
	AUDITLOG,
	CC,
	E_MYSQL,
	TYPE_MAX
};

struct datatype {
	char    *name;
	int     (*line_f)(char *line, char *end);
};

struct chunk {
	char *str;
	int len;
};
#endif 
