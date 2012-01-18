/*******************************************
   Smunge. 

   POP-3 Funnelling Proxy.

   Distributed under the terms of the
   GNU General Public License.

   See LICENSE File for license details.

   Copyright (c) Joshua Reich 2000
   http://www.i2pi.com/smunge/
********************************************/

#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <signal.h>
#include <sys/uio.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <fnmatch.h>

#include "config.h"
#include "mail.h"
#include "server.h"
#include "smunge.h"
#include "sm_ldap.h"

int	uidl_mod = 0;

int	abfab (int fd, char *p, size_t i)
{
	if ( (fd < 0) || (p == NULL) )
	{
		return -1;
	}

	return (write (fd, p, i));
}

int	to_client (int fd, char *str)
{	
	if ( (fd < 0) || (str == NULL) )
	{
		return -1;
	}

	if (abfab (fd, str, sizeof (char) * strlen (str) ) < 0)
	{
		// Error
		return (-1);
	}
	if (LOG_LEVEL > 49)
	{
		if (DEBUG)	
		{	
			printf ("%d --> %s\n", fd, str);
		}
		syslog (LOG_DEBUG, "%d -->%s",fd, str);
	}
	abfab (fd, CRLF, 2*sizeof (char));

	return (0);
}


int	get_command (int *fd, char *argv0, char *argv1, char *argv2, char *argv3)
{
	// Waits for an incoming command, reads up to, and including
	// a '\n'. Breaks up incoming data into command, and if any,
	// arguments. (arguments are seperated by spaces)

	char	*p;
	fd_set	read_set;	
	struct timeval	tv;
	int	i, argc, r, j;
	float 	idle_time;

	if (*fd < 0)
	{
		return -1;
	}
 
	i = 0;
	argc = 0;
	r = 1;
	p = argv3;
	idle_time = 0.0;

	FD_ZERO (&read_set);
	
	argv0[0] = argv1[0] = argv2[0] = argv3[0] = 0;

	while ((i < MAX_LINE-3) && (*fd > 0) && (r == 1) )
	{
		tv.tv_sec = SELECT_SEC;
		tv.tv_usec = SELECT_USEC;
		FD_SET (*fd, &read_set);
		if (select (*fd+1, &read_set, NULL, NULL, &tv) < 0)
		{
			return (-2);
		}
		if (*fd < 1)
		{
			return (-3);
		}
		if (FD_ISSET (*fd, &read_set))
		{
			idle_time = 0.0;

			if (*fd < 1)
			{
				return (-3);
			}

			switch (argc)
			{
				case 0: p = argv0; break;
				case 1: p = argv1; break;
				case 2: p = argv2; break;
				case 3: p = argv3; break;
			}

			r = read(*fd, &p[i], 1);

			if (p[i] == '\n')
			{
				break;
			}

			// if we got a ' ', then we have a New argument.
			if (!argc) p[i] = toupper (p[i]);
			if ((i >= 1) && (p[i-1] != ' ') && (p[i] == ' ') && (argc < 3))
			{
				argc++;
				p[i] = 0;
				i = 0;
			} else
			if (p[i] != ' ')
			{
				i++;
			}	
		} else
		{
			// They are idling

			idle_time += SELECT_SEC + (SELECT_USEC * 0.0001);
			if ((int)idle_time > MAX_IDLE)
			{
				return (-1);
			}
		}
	}


	for (j=0; j < i; j++)
	{
		if ((p[j] == '\n') || (p[j] == '\r'))	
		{
			p[j] = 0;
		}
	}
	p[i]=0;
	argc++;

	if (LOG_LEVEL > 49)
	{ 

		if (DEBUG)
		{
			printf ("%d <-- %s, %s, %s, %s -  %d\n", *fd, argv0, argv1, argv2, argv3, argc);
		}
	}

	if (i >= MAX_LINE)
	{
		p[i-1] = 0;
	} 
	if (r < 1)
	{
		return (-1);
	}

	return (argc);
}

int	err (userT *user, char *str)
{	
	int	fd = user->fd;

	if ( (fd < 0) || (str == NULL) )
	{
		return (-1);
	}

	user->errors++;

	if (abfab (fd, ERR, sizeof (char) * (strlen (ERR))) < 0)
	{
		// Error
		return (-1);
	}

	abfab (fd, " ", sizeof (char));
	abfab (fd, " ", sizeof (char));
	abfab (fd, str, sizeof (char) * (strlen (str)));
	abfab (fd, CRLF, 2*sizeof (char));

	if (LOG_LEVEL > 39)
	{
#ifdef DBUG
		printf ("%s: -ERR %s\n", user->username, str);
#endif
		syslog (LOG_NOTICE, "%s: -ERR %s\n", user->username, str);
	}

	watchdog (user);

	return (0);
}

int	ok (int fd, char *str)
{	
	if ( (fd < 0) || (str == NULL) )
	{
		return (-1);
	}

	if (abfab (fd, OK, sizeof (char) * (strlen (OK))) < 0)
	{
		// Error
		return (-1);
	}

	abfab (fd, " ", sizeof (char));	
	abfab (fd, str, sizeof (char) * (strlen (str)));
	
	abfab (fd, CRLF, sizeof (char)*2);

	return (0);
}


struct hostent	*gethostbyjosh (char *hostname)
{
	/* A OS independant wrapper to gethostbyname */

	struct hostent 	*host;

#ifndef FREEBSD
	char		hostbuf[HOSTBUF_LEN];
	int	errn;
#endif

	host = (struct hostent *) malloc (sizeof (struct hostent));

#ifdef SOLARIS
	gethostbyname_r (hostname, host, hostbuf, HOSTBUF_LEN, &errn);
#endif

#ifdef LINUX
	gethostbyname_r (hostname, host, hostbuf, (size_t) HOSTBUF_LEN, &host, &errn);
#endif
	
#ifdef FREEBSD
	host = gethostbyname (hostname);
#endif

	if (host == NULL)
	{
		fprintf (stderr, "adding popserver '%s':\n", hostname);
		perror ("gethostbyjosh");
		exit (-1);
	}

	return (host);
}


void	my_hash (char *str, char *hash, char digits)
{
	int	i;
	int	val = 0;

	// I know this sucks, but i dont want to
	// include math.h and dont need double,
	// so perhaps its faster.

	if (uidl_mod == 0)
	{
		uidl_mod = UIDL_RANGE;
		for (i = 1; i < digits; i++)
		{
			uidl_mod *= UIDL_RANGE;
		}
	}


	for (i = 0; i < strlen (str); i++)
	{
		val += str[i];
		val %= uidl_mod;	
	}

	i = 0;

	while (val)
	{
		hash[i++] = val % UIDL_RANGE + UIDL_BASE;
		val /= UIDL_RANGE;
	}

	hash[i] = 0;
}

mailboxT	*add_user_mailbox (userT *user, char *hostname, struct hostent *host, int port, char *alt_username)
{
	int		n;
	
	if (host == NULL)
	{
		// Need to lookup the stuffs
		// 
		
		host = gethostbyjosh (hostname);	
	}

	n = user->mailboxes++;
	user->mailbox[n].username[0] = '\0';
	user->mailbox[n].host = host;
	strncpy (user->mailbox[n].hostname, hostname, MAX_HOSTNAME-1);
	user->mailbox[n].port = port;
	user->mailbox[n].up_to_date = 0;
	user->mailbox[n].messages = 0;
	user->mailbox[n].total_size = 0;
	user->mailbox[n].fd = -1;
	user->mailbox[n].message = NULL;

	if (alt_username != NULL)
	{
		strncpy (user->mailbox[n].username, alt_username, MAX_USERPASS-1);
	}

	if (SMUNGE_UIDL > 0)
	{
		char	str[MAX_HOSTNAME+8];

		if (alt_username != NULL)
		{
			snprintf (str, MAX_HOSTNAME+7, "%s%d%s", hostname, port, alt_username);
		} else		
		{
			snprintf (str, MAX_HOSTNAME+7, "%s%d", hostname, port);
		}

		my_hash (str, user->mailbox[n].uidl_hash, 2);
	}

	return (&user->mailbox[n]);
}
	
int	get_mailboxes (userT *user)
{
	int	i = 0;
	int 	matched = 0;

	while ( (i < MAX_POPSERVERS) && (popserver[i].host != NULL))
	{

		// Should check patterns.. doesnt for the moment

		if (popserver[i].pattern[0] != NULL)
		{
			int p = 0;

			matched = 0;

			while ( (p < MAX_PATTERNS) && (popserver[i].pattern[p] != NULL) )
			{
				if (!fnmatch (popserver[i].pattern[p], user->username, 0))
				{
					matched = 1;
					if (DEBUG && (LOG_LEVEL > 29))
					{
						printf ("Matched '%s' against '%s'\n", popserver[i].pattern[p], user->username);
					}
					break;
				}
				p++;
			}
		} else
		{
			matched = 1;
		}
				
		if (matched)
		{
			if (DEBUG && (LOG_LEVEL > 29))
			{
				printf ("Adding '%s' to swag of %s\'s mailboxes\n", popserver[i].hostname, user->username);
			}

			add_user_mailbox (user, popserver[i].hostname, popserver[i].host, popserver[i].port, NULL);
		}


		i++;
	}

	return (0);
}

userT	*new_connection (userT *user)
{
	// First thing to do is to get USER and PASS
	
	int	box;
	int	argc;
	char	argv0[MAX_ARG_LEN];
	char	argv1[MAX_ARG_LEN];
	char	argv2[MAX_ARG_LEN];
	char	argv3[MAX_ARG_LEN];
	
	user->errors = 0;
	user->time = 0;
	user->password[0] = 0;
	user->username[0] = 0;	
	user->mailboxes = 0;

	for (box = 0; box < MAX_POPSERVERS; box++)
	{
		user->mailbox[box].host = NULL;
		user->mailbox[box].fd = -1;
		user->mailbox[box].messages = 1;
		user->mailbox[box].message = NULL;
	}


	while (!user->username[0] || !user->password[0])
	{
		if ((argc=get_command (&user->fd, argv0, argv1, argv2, argv3)) < 0)
		{
			break;
		}

		if ((argv0 == NULL) || (argc == 0))
		{
			// Doing nothing
		} else
		if (!strcmp (argv0, "QUIT"))
		{
			quit (user);
			ok (user->fd, "Short but sweet");
			return (0);
		} else
		if (argc != 2)
		{
			err (user, "You must login first");
		} else
		if (!strcmp (argv0, "PASS") && !user->username[0])
		{
			err (user, "You must supply username before password");
		} else
		if (!strcmp (argv0, "USER"))
		{
			strncpy  (user->username, argv1, MAX_USERPASS-1);
			ok (user->fd, "Please enter your pass, with the PASS command");		
		} else
		if (!strcmp (argv0, "PASS") && user->username[0])
		{
			if (argv1[0])
			{
				strncpy  (user->password, argv1, MAX_USERPASS-1);
			} else
			{
				err (user, "Invalid password");
				return (0);
			}
		} else
		{
			err (user, "Invalid command");
		}

	}

	if (!user->username[0] || !user->password[0])
	{
		return (0);
		return (NULL);
	}
	
	user->mailboxes = 0;

#ifdef USE_LDAP
	if (SM_LDAP_AUTH || SM_LDAP_POP)
	{
		// Force an authentication against LDAP
		
		char	**pop_hosts;
		int	num;
		
		if (SM_LDAP_POP)
		{
			pop_hosts = (char **) malloc (sizeof (char *) * MAX_LDAP_POPS);
		} else
		{
			pop_hosts = NULL;
		}
		
		if  ( (num = ldap_auth (user->username, user->password, pop_hosts)) != 0)
		{
			// Failed
			
			if (LOG_LEVEL > 9)
			{
				if (DEBUG)
				{
					fprintf (stderr, "Failed LDAP auth for %s on %s:%d [%s]\n", user->username, SM_LDAP_HOST, SM_LDAP_PORT, ldap_auth_err_codes[num]);
				}
				
				syslog (LOG_NOTICE, "Failed LDAP auth for %s on %s:%d [%s]\n", user->username, SM_LDAP_HOST, SM_LDAP_PORT, ldap_auth_err_codes[num]);
			}
			
			return (0);
		} else
		if (num > 0)
		{
			// Ok, and we got some pophosts back
			
			char	*hostname;
			char	*username;
			char	*p;
			int	j;
			int	port;
			struct hostent	*host;
			
			for (j = 0; j < num; j++)
			{
				hostname = strtok (pop_hosts[j], ":");
				username = NULL;

				// Check to see if the hostname has a user@ bit.. if so, steal the username
				
				p = strchr (hostname, '@');
				if (p != NULL)
				{
					username = (char *) malloc (sizeof (char) * (p - hostname + 1));
					strncpy (username, hostname, (p - hostname));
					username[p - hostname] = '\0';

					host = gethostbyjosh (&p[1]);
				} else
				{
					host = gethostbyjosh (hostname);
				}
				
				if (host)
				{
					mailboxT	*mailbox;

					if ( (p = strtok (NULL, ":")) != NULL )
					{
						port = atol (p);		
					} else
					{
						port = 110;
					}
				
					mailbox = add_user_mailbox (user, hostname, host, port, username);
				} else
				{
					if (LOG_LEVEL > 9)
					{
						if (DEBUG)
						{
							fprintf (stderr, "Failed lookup of host %s\n", hostname);
						}
						syslog (LOG_NOTICE, "Failed lookup of host '%s'\n", hostname);
					}
				}

			}
			
		}
	}
#endif
	user->time = time(NULL);

	// Now get the users mailboxes
	if (get_mailboxes (user))
	{
		// Failed reading their mailboxes,
		// so act as if they never logged in
		return (0);
	}

	// Now log them in
	if (!login (user))
	{

		// Cool
		ok (user->fd, "Well done!");

		return (user);
	} else
	{
		err (user, "Invalid login");
		return (0);
	}

	return (0);
	return (NULL);
}

void	new_server_thread (int con, struct sockaddr_in *cliaddr, int *len)
{
	userT		*user = (userT *) malloc (sizeof (userT));

	user->fd = con;
	memcpy (&user->sin_addr, &cliaddr->sin_addr, sizeof (struct in_addr));

	if (getpeername (con, (struct sockaddr *) cliaddr, len) < 0)
	{
		// Couldn't determine remote peer name
		
		syslog (LOG_CRIT, "Couldn't determine remote peer address");
		return;
	} else
	{
		strncpy (user->peername, inet_ntoa (cliaddr->sin_addr), 
			MAX_ARPA_ADDR);
	}

	if (!to_client (user->fd, GREETING))
	{
		user->time = time(NULL);
		if (new_connection(user))
		{
			user->errors = 0;
			smunge (user);
		}
	}

	return ;
}

void	kill_conn (userT *user)
{
	int 	box;

	if (LOG_LEVEL > 29)
	{
		if (DEBUG)
		{
			printf ("Killing %s (fd %d) : Errors %d (%d), Idle %ld sec \n",
				user->username, user->fd, 
				user->errors,
				MAX_ERRORS,
				(long)(time(NULL) - user->time));
		}
	}

	if (user->fd < 0)
	{
		return;
	}

	if ( user->mailboxes < MAX_POPSERVERS )
	 for (box = 0; box < user->mailboxes ; box++)
	{
		if (LOG_LEVEL > 29)
		{
			if (DEBUG)
			{
				printf ("Closing connection popserver %d\n", box);
			}
		}
		if ((user->mailbox[box].fd != -1) && close (user->mailbox[box].fd))
		{
			// prolly from closing it twice...
			perror ("*** close popside fd");
		}

		user->mailbox[box].fd = -1;
		user->mailbox[box].host = NULL;
		free (user->mailbox[box].message);
		user->mailbox[box].message = NULL;
	}

	if (close (user->fd))
	{
		perror ("*** Close user fd");
	} 

	user->fd = -1;
}

void	watchdog (userT *user)
{
	if ( 
	     ( 
		(time(NULL) - user->time > MAX_IDLE) &&
	       	(user->time) 
	     ) ||
	     (
		(user->errors >= MAX_ERRORS)
	     ) 
	   )	
	{
		kill_conn (user);
		return ;
	}
}		

int	start_server (void)
{
	int			connfd;
#if !defined(SOLARIS)
	socklen_t		len;
#else
	int			len;
#endif
	struct sockaddr_in	servaddr, cliaddr;
	int			j;


		
	if ((listenfd = socket (AF_INET, SOCK_STREAM, 0)) == -1)
	{
		if (LOG_LEVEL > 9)
		{
			if (DEBUG)
			{
				perror ("start_server socket"); 
			}
			syslog (LOG_NOTICE, "start_server socket: %m"); 
		}
		exit (-1);
	}

	j = 1;
	setsockopt (listenfd, SOL_SOCKET, SO_REUSEADDR, (void *) &j, sizeof(int));

	bzero (&servaddr, sizeof (servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl (INADDR_ANY);
	servaddr.sin_port = htons (PORT);

	if (bind (listenfd, (struct sockaddr *) &servaddr, sizeof (servaddr)) ==-1)
	{
		if (LOG_LEVEL > 9)
		{
			if (DEBUG)
			{
				perror ("start_server bind");
			}
			syslog (LOG_NOTICE, "start_server bind: %m"); 
		}
		exit (-1);
	}

	if (listen (listenfd, BACKLOG) == -1)
	{
		if (LOG_LEVEL > 9)
		{
			if (DEBUG)
			{
				perror ("start_server listen");
			}
			syslog (LOG_NOTICE, "start_server listen: %m"); 
		}
		exit (-1);
	}

	if (LOG_LEVEL > 9)
	{
		if (DEBUG)
		{
			printf ("Server started on port %d\n", PORT);
		}
		syslog (LOG_NOTICE, "Server started on port %d\n", PORT);
	}
	while (1)
	{
		len = sizeof (cliaddr);
		connfd = accept (listenfd, (struct sockaddr *) &cliaddr, &len);

		if (LOG_LEVEL > 59)
		{
			if (DEBUG)
			{
				printf ("Starting new client connection\n"); 
			}
			syslog (LOG_DEBUG, "Starting new client connection '%d'\n", connfd);
		}

		/*
		** Suggested by Ricky Chan. 2003-03-05
		*/

		if (connfd < 0)
		{
			continue;
		}
	
		if (!fork ())
		{
			close (listenfd);
			seteuid (EUID);
			setegid (EGID);
			new_server_thread (connfd, &cliaddr, &len);
			exit (0);
		}	

		close (connfd);
	}

	return (-5);
}
