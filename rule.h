#ifndef RULE_TREE_H
#define RULE_TREE_H

#include <sys/types.h>
#include <regex.h>
#include "fetch.h"
enum tnode_type {TNUL, OPERAND, OPERATOR, PARETHESE};
enum tnode_name {NNUL, AND, OR, NOT, /*NUL = -1*/};
//enum tnode_ret  {FALSE, TRUE};
enum tnode_opet {REGEX, STREQ, EQ, GT, LT, GE, LE, NE, OPET_MAX};

struct tree_node
{
	enum tnode_type type;
	union {
		enum tnode_name oname;
		enum log_entry ename;
	}name;
	enum tnode_opet op;
	union {
		int inte;
		char *str;
		regex_t reg;
	}operand;

	int ret;

	int rvisited;
	struct tree_node *left;
	struct tree_node *right;
	struct tree_node *parent;
};

struct stack {
	struct tree_node *top;
	struct tree_node *base;

	int size;
};

struct opet_map{
	char *name;
	enum tnode_opet opet;
};

extern struct opet_map opet_map[];
int init_stack(void);
int push(struct tree_node *entry);
struct tree_node *pop();
struct tree_node *gen_rule_tree();
int traverse_rule_tree(void *log, struct tree_node *root);
#endif
