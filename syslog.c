#include "syslog.h"

void tcp_syslog(char *dst, char *port, char *buf)
{
	int sfd, val;
	
	sfd = socket(AF_INET, SOCK_STREAM, 0);
	val = fcntl(sfd, F_GETFL);
	fcntl(sfd, F_SETFL, val|O_NONBLOCK);
}

int syslog(char *dst, char *port, enum protocol, char *buf)
{
	switch (protocol) {
		case UNIX:
			unix_syslog(dst, port, buf);
			break;
		case UDP:
			udp_syslog(dst, port, buf);
			break;
		case TCP:
			tcp_syslog(dst, port, buf);
			break;
	}
}
