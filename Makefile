CC=gcc
CFLAGS=-Wall -c -O -g
LDFLAGS=-L/usr/lib64 -lmysqlclient -Wall
PROG=push_log
DESTDIR ?=

all: $(PROG)

$(PROG): push_log.o daemon.o database.o fetch.o log.o parse_auditlog.o parse_conf_file.o rule.o
	$(CC) $(LDFLAGS) -o $@ $^
push_log.o: push_log.c
	$(CC) $(CFLAGS) push_log.c
	
daemon.o: daemon.c
	$(CC) $(CFLAGS) daemon.c

database.o: database.c
	$(CC) $(CFLAGS) database.c

fetch.o: fetch.c
	$(CC) $(CFLAGS) fetch.c

log.o: log.c
	$(CC) $(CFLAGS) log.c

parse_auditlog.o: parse_auditlog.c
	$(CC) $(CFLAGS) parse_auditlog.c

parse_conf_file.o: parse_conf_file.c
	$(CC) $(CFLAGS) parse_conf_file.c

rule.o: rule.c
	$(CC) $(CFLAGS) rule.c

.PHONY: clean

clean:
	rm -rf *.o $(PROG) tags
