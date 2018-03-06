#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "rule.h"
#include "parse_conf_file.h"

#define STACKINCREMENT 50
struct stack s;

struct opet_map opet_map[] = {
	[REGEX] = {
		.name = "regex",
		.opet = REGEX},
	[STREQ] = {
		.name = "streq",
		.opet = STREQ},
	[EQ] = {
		.name = "==",
		.opet = EQ},
	[GT] = {
		.name = ">",
		.opet = GT},
	[LT] = {
		.name = "<",
		.opet = LT},
	[GE] {
		.name = ">=",
		.opet = GE},
	[LE] = {
		.name = "<=",
		.opet = LE},
	[NE] = {
		.name = "!=",
		.opet = NE},
	[OPET_MAX] = {
		.name = NULL,
		.opet = OPET_MAX},
};

int init_stack(void)
{
	if ((s.base = calloc(stack_size, sizeof(struct tree_node *))) == NULL) {
		logg("failed to alloc stack");
		return 0;
	}

	s.top = s.base;
	s.size = stack_size;
	return 1;
}

int push(struct tree_node *entry)
{
	if (s.top - s.base >= s.size) {
		s.base = (struct tree_node *)realloc(s.base, (s.size + STACKINCREMENT) * sizeof(struct tree_node *));
		if (!s.base) {
			logg("failed to realloc stack");
			return 0;
		}

		s.top = s.base + s.size;
		s.size += STACKINCREMENT;
	}

	s.top = entry;
	s.top++;

	return 1;
}

struct tree_node *pop()
{
	struct tree_node *entry;

	if (s.base == s.top)
		return NULL;

	entry = --s.top;

	return entry;
}

int stack_is_empty()
{
	if (s.base == s.top)
		return 1;

	return 0;
}

struct tree_node *get_top()
{
	if (s.base == s.top)
		return NULL;

	return (s.top - 1);
}

static void calc_node_val(void *log, struct tree_node *t)
{
	//enum events_type type;
	//struct alarm_info *ainfo;
	struct chunk *chunk;
	char databuf[1024];
	char *data;

#if 0
	memcpy(&type, log, sizeof(enum events_type));
	if (type == AUDITLOG)
		ainfo = (struct alarm_info *)log;
	else if (type == CC) {
	}
#endif
	
	if (t->type == OPERATOR) {
		if (t->name.oname == AND)
			t->ret = t->right->ret && t->left->ret;
		else if (t->name.oname == OR)
			t->ret = t->right->ret || t->left->ret;
		else if (t->name.oname == NOT)
			t->ret = !(t->left->ret);
	} else if (t->type == OPERAND) {
		chunk = map[t->name.ename].fetch(log);

		if (chunk->len != -1) {
			snprintf(databuf, chunk->len + 1, "%s", chunk->str);
			data = databuf;
		} else {
			data = chunk->str;
		}

		if (t->op == REGEX) {
			t->ret = !regexec(&t->operand.reg, data, 0, NULL, 0);
		} else if (t->op == STREQ) {
			t->ret = !strcmp(t->operand.str, data);
		} else if (t->op == EQ) {
			t->ret = (t->operand.inte == atoi(data));
		} else if (t->op == GT) {
			t->ret = (atoi(data) > t->operand.inte);
		} else if (t->op == LT) {
			t->ret = (atoi(data) < t->operand.inte);
		} else if (t->op == GE) {
			t->ret = (atoi(data) >= t->operand.inte);
		} else if (t->op == LE) {
			t->ret = (atoi(data) <= t->operand.inte);
		} else if (t->op == NE) {
			t->ret = (atoi(data) != t->operand.inte);
		}
	}
}

struct tree_node *gen_rule_tree()
{
	struct tree_node *root = NULL, *node, *prev = NULL;
	int changle_root = 1;

	for (; !stack_is_empty(); prev = node) {
		node = pop();
#if 0
		if (node == NULL) {
			return root;
		}
#endif

		if (node->type == PARETHESE) {
			push(root);
			free(node);
			return NULL;
		}
		
		if (prev == NULL) {
			root = node;
			continue;
		} else if (changle_root) {
			root->parent = node;
			node->left = root;
			root = node;
			changle_root = 0;
			continue;
		}

		if (node->type == OPERATOR && prev->type == OPERAND) {
			node->left = prev;

			if (prev->parent->right != NULL) {
				prev->parent->right = node;
			} else {
				prev->parent->left = node;
			}

			node->parent = prev->parent;
			prev->parent = node;
			continue;
		}

		if (prev->left == NULL) {
			prev->left = node;
		} else {
			prev->right = node;
		}
		node->parent = prev;
	}

	return root;
}

/* 后序遍历二叉树 root 
 * @root B_tree`s root
 * @log  log
 * */
int traverse_rule_tree(void *log, struct tree_node *root)
{
	struct tree_node *t;

	push(root);
	while (!stack_is_empty()){
		while ((t = get_top()) != NULL)
			push(t->left);
		pop(); 					/* pop() the NULL node */

		t = get_top();
		if (t->right == NULL || t->rvisited == 1) {
			t = pop();
			calc_node_val(log, t);
		} else {
			t->rvisited = 1;
			push(t->right);
		}
	}

	return root->ret;
}
