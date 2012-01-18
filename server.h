/*******************************************
   Smunge. 

   POP-3 Funnelling Proxy.

   Distributed under the terms of the
   GNU General Public License.

   See LICENSE File for license details.

   Copyright (c) Joshua Reich 2000
   http://www.i2pi.com/smunge/
********************************************/


#ifndef SERVER_H

#define GREETING	"+OK Smunge POP v1.3.6alpha"
#define BACKLOG		20
#define MAX_LINE	2048
#define MAX_ARG_LEN	80
#define ERR		"-ERR"
#define OK		"+OK"
#define SELECT_SEC	0	
#define SELECT_USEC	200
#define CRLF		"\r\n"
#define UIDL_BASE	0x21
#define UIDL_TOP	0x7E
#define UIDL_RANGE	(0x7E - 0x21)

#include <time.h>

#include "mail.h"
#include "config.h"

int		listenfd;
extern int	uidl_mod;

int	abfab (int fd, char *p, size_t i);
int	start_server	(void);
int	to_client (int fd, char *str);
int	get_command (int *fd, char *argv0, char *argv1, char *argv2, char *argv3);
int	ok (int fd, char *str);
int	err (userT *user, char *str);
void	kill_conn (userT *user);
void	watchdog (userT *user);

#define SERVER_H
#endif
