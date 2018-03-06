#ifndef DAEMON_H
#define DAEMON_H

#define PID_FILE_PATH "/var/run/log_input.pid"
#define CMD_LINE "log_input"

void usage ();
void start ();
void stop ();
void restart ();

#endif
