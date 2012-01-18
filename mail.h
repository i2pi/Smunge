/*******************************************
   Smunge. 

   POP-3 Funnelling Proxy.

   Distributed under the terms of the
   GNU General Public License.

   See LICENSE File for license details.

   Copyright (c) Joshua Reich 2000
   http://www.i2pi.com/smunge/
********************************************/




#ifndef MAIL_H

#include <sys/time.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define LIST_FLAG	4
#define MAX_UIDL	70
#define MAX_USERPASS	40
#define MAX_MESSAGES	8192	
#define MAX_HOSTNAME	256
#define MAX_HOST_LEN	256
#define MAX_FUNC_LEN	256
#define MAX_PATTERNS	8	
#define MAX_POPSERVERS	32	
#define HOSTBUF_LEN	8192
#define MAX_HOST_HASH	16
#define MAX_ARPA_ADDR	64

#define CRLFDOTCRLF	"\r\n.\r\n"

typedef struct _popserver
{
	char		hostname[MAX_HOSTNAME];
	char		hostbuf[HOSTBUF_LEN];
	struct hostent	*host;
	int		port;
	char		*pattern[MAX_PATTERNS];
} popserverT;

typedef struct _message
{
	char		uidl[MAX_UIDL+1];
	long		size;
	char		deleted;
} messageT;

typedef struct _mailbox
{
	struct hostent 	*host;	
	char		username[MAX_USERPASS];
	char		hostname[MAX_HOSTNAME];
	int		port;
	int		fd;
	char		up_to_date;
	long		messages;
	long		total_size;
	messageT	*message;	
	char		uidl_hash[MAX_HOST_HASH];
} mailboxT;

typedef struct _user 
{
	char		username[MAX_USERPASS];
	char		peername[MAX_ARPA_ADDR];
	char		password[MAX_USERPASS];
	int		mailboxes;
	mailboxT	mailbox[MAX_POPSERVERS];
	int		fd;
	int		errors;
	time_t		time;
	char		current_function[MAX_FUNC_LEN];
	struct in_addr	sin_addr;
} userT;

extern struct timeval		READ_BLOCK_WAIT;
extern popserverT		popserver[MAX_POPSERVERS];

int	login (userT *user);
int	status (userT *user, int box, long *messages, long *size);
int	list (userT *user);
int	list_s (userT *user, long num);
int	retr (userT *user, long num, long lines);
int	dele (userT *user, long arg);
int	rset (userT *user);
int	quit (userT *user);
int	uidl (userT *user);
int	uidl_s (userT *user, long num);
int	debug (userT *user);


#define MAIL_H
#endif
