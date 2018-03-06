#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include "log.h"
#include "daemon.h"

static void delete_pid_file ()
{
	if (remove (PID_FILE_PATH) == -1) {
		logg ("[delete_pid_file] failed to remove %s\n", PID_FILE_PATH);
	}
}

void usage ()
{
	fprintf (stderr, "usage: %s {start, stop, restart}\n", CMD_LINE);
}

static void create_pid_file ()
{
	FILE	*fp;
	char	cmd_path[20];
	char	comm[50];
	int	pid = 0;

	memset (cmd_path, 0, 20);
	memset (comm, 0, 50);

	if (access (PID_FILE_PATH, F_OK) == 0) {
		fp = fopen (PID_FILE_PATH, "r");
		fscanf (fp, "%d", &pid);
		fclose (fp);

		if (pid != 0) {
			sprintf (cmd_path, "/proc/%d/comm", pid);
			if ((fp = fopen (cmd_path, "r")) != NULL) {
				fscanf (fp,  "%s", comm);
				fclose (fp);
				if (strstr (comm, CMD_LINE) != NULL) {
					logg ("process already exist, exit\n");
					exit (1);
				}
			}
		}
	}

	if ((fp = fopen (PID_FILE_PATH, "w")) != NULL) {
		fprintf (fp, "%d\n", getpid());
		fclose (fp);
	} else {
		logg ("[start] failed to open %s for write\n", PID_FILE_PATH);
	}
}

void start ()
{
	daemon (0, 0);
	create_pid_file ();
	logg ("<up>\n");
}

void stop ()
{
	FILE	*fp;
	pid_t	pid = 0;

	if (access (PID_FILE_PATH, F_OK) == -1)
		return;

	if ((fp = fopen (PID_FILE_PATH, "r")) == NULL) {
		logg ("[stop] failed to open %s\n", PID_FILE_PATH);
		return;
	}

	fscanf (fp, "%d", &pid);

	if (pid == 0)
		return;

	while (1) {
		if (kill (- pid, SIGTERM) == -1 && errno == ESRCH)
			break;
	//	sleep (1);
	}

	if (access (PID_FILE_PATH, F_OK) == 0)
		delete_pid_file ();
}

void restart ()
{
	stop();
	start();
}
