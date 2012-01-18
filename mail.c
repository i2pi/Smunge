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
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>

#include "server.h"
#include "mail.h"
#include "config.h"


popserverT	popserver[MAX_POPSERVERS];

#ifdef USE_DRAC
extern int dracauth (char *server, unsigned long userip, char **errmsg);
#endif


int	terminate (int fd)
{
	/* Sends a CRLFDOTCRLF to a fd */

	if (fd < 1)
	{
		return -1;
	}

	return (abfab (fd, CRLFDOTCRLF, 5));
}

int	send_pop (mailboxT *mailbox, char *str)
{
	/* Sends a string to a mailbox */
		
	if ((mailbox == NULL) || (mailbox->fd < 1))
	{
		return -1;
	}

	if (abfab (mailbox->fd, str, sizeof (char) * (strlen (str))) < 0)
	{
		// Error
		return (-1);
	}
	
	abfab (mailbox->fd, CRLF, 2*sizeof (char));

	if (LOG_LEVEL > 49)
	{
		if (DEBUG)
		{
			printf ("%d --> '%s'\n", mailbox->port, str);
		}
		syslog (LOG_DEBUG, "%s:%d --> '%s'\n", mailbox->host, mailbox->port, str);
	}
	return (0);
}

int	get_ok (mailboxT *mailbox)
{
	int	argc;
	char	argv0[MAX_ARG_LEN];
	char	argv1[MAX_ARG_LEN];

	if ((mailbox == NULL) || (mailbox->fd < 0))
	{
		return -1;
	}

	if ((argc=get_command (&mailbox->fd, argv0, argv1, argv1, argv1)) < 0)
	{
		return (-1);
	}
	if (argc && (!strcmp (argv0, OK)))
	{
		return (0);
	}
	
	return (1);
}



int	pop_client (userT *user, int box)
{

	/* Establishes a connection with a users pop server */

	int			sockfd;
	struct hostent		*hostinfo;
	struct sockaddr_in	servaddr;
	char			str[MAX_LINE];
	mailboxT		*mailbox;
	int			r;

	if (DEBUG)
	{
		snprintf (user->current_function, MAX_FUNC_LEN - 2, "pop_client (user, %d)", box);
	}

	if (user == NULL)
	{
		return -1;
	} else
	if (user->mailboxes <= box)
	{
		return -1;
	}

	mailbox = &user->mailbox[box];
	if (mailbox->host == NULL)
	{
		return (-1);
	}


	hostinfo = mailbox->host;

	bzero (&servaddr, sizeof (servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons (mailbox->port);
	servaddr.sin_addr = *((struct in_addr *) hostinfo->h_addr_list[0]);

	if ( (sockfd = socket (AF_INET, SOCK_STREAM, 0)) == -1)
	{
		if (LOG_LEVEL > 9)
		{
			if (DEBUG)
			{
				fprintf (stderr, "connect: %m (%s:%d)", mailbox->hostname,mailbox->port);
				perror ("socket");
			}
			syslog (LOG_NOTICE, "socket: %m (%s:%d)", mailbox->hostname,mailbox->port);
		}
		return (-1);
	}

	if (connect (sockfd, (struct sockaddr *) &servaddr, sizeof (servaddr)))
	{
		if (LOG_LEVEL > 9)
		{
			if (DEBUG)
			{
				fprintf (stderr, "connect: %m (%s:%d)", mailbox->hostname,mailbox->port);
				perror ("connect");
			}
			syslog (LOG_NOTICE, "connect: %m (%s:%d)", mailbox->hostname,mailbox->port);
		}
		// Lets kill the mailbox
		mailbox->fd = -1;
		mailbox->port = -1;
		return (-1);
	}

	// Ok, we have connected, so lets do authenticate

	mailbox->fd = sockfd;

	// Expect OK
	r = get_ok (mailbox);

	if (!r)
	{
		if (mailbox->username[0] != '\0')
		{
			snprintf (str, MAX_LINE-1, "USER %s", mailbox->username);
		} else
		{
			snprintf (str, MAX_LINE-1, "USER %s", user->username);
		}

		send_pop (mailbox, str);
		r=get_ok (mailbox);

		if (!r)
		{
			snprintf (str, MAX_LINE-1, "PASS %s", user->password);

			send_pop (mailbox, str);
			r=get_ok (mailbox);

			if (!r)
			{
				// Authenticated

#ifdef USE_DRAC
				if (DRAC_AUTH && !DRAC_HOST)
				{
					// Now need to drac them.
					// Assumes drac is running on the pop server
					char 	*dracerr;
			
					if (dracauth (mailbox->hostname, user->sin_addr.s_addr, &dracerr) != 0)
					{
						if (LOG_LEVEL > 9)
						{
							if (DEBUG)
							{
								printf ("DRAC authentication error for %s on %s (%s)\n", user->username, mailbox->hostname, dracerr);
							}
	
							syslog (LOG_ALERT, "DRAC authentication error for %s on %s (%s)\n", user->username, mailbox->hostname, dracerr);
						}	
					} else
					if (LOG_LEVEL > 19)
					{
						if (DEBUG)
						{
							printf ("DRAC authentication OK %s on %s\n", user->username, mailbox->hostname);
						}
	
						syslog (LOG_ALERT, "DRAC authentication OK for %s on %s\n", user->username, mailbox->hostname);
					}
				}
#endif
				return (0);
			} else
			{
				// Invalid Password
				return (-2);
			}
		} else
		{
			return (-3);
			close (mailbox->fd);
		}
	}

	close (mailbox->fd);

	return (-4);
}

int	login (userT *user)
{
	// Go through all the users mailboxes and authenticate

	int	i, boxes;

	boxes = 0;

	if (user == NULL)
	{
		return -1;
	}

	if (DEBUG)
	{
		snprintf (user->current_function, MAX_FUNC_LEN - 2, "login");
	}
	
	for (i = 0; i < user->mailboxes; i++)
	{
		if (!pop_client (user, i))
		{
#ifdef USE_DRAC
			if (DRAC_AUTH && DRAC_HOST)
			{
				// Now need to drac them against the supplied DRAC_HOST

				char 	*dracerr;
		
				if (dracauth (DRAC_HOST, user->sin_addr.s_addr, &dracerr) != 0)
				{
					if (LOG_LEVEL > 9)
					{
						if (DEBUG)
						{
							printf ("DRAC authentication error for %s on %s (%s)\n", user->username, DRAC_HOST, dracerr);
						}

						syslog (LOG_ALERT, "DRAC authentication error for %s on %s (%s)\n", user->username, DRAC_HOST, dracerr);
					}	
				} else
				if (LOG_LEVEL > 19)
				{
					if (DEBUG)
					{
						printf ("DRAC authentication OK %s on %s\n", user->username, DRAC_HOST);
					}
					
					syslog (LOG_ALERT, "DRAC authentication OK %s on %s\n", user->username, DRAC_HOST);
				}
			}
#endif
					
			if (LOG_LEVEL > 19) 
			{
				if (DEBUG)
				{
					printf ("%s connected to mailbox %s\n", user->username, user->mailbox[i].hostname);	
				}
				syslog (LOG_INFO, "%s@[%s] connected to %s\n", user->username, user->peername, user->mailbox[i].hostname);	
			}
			boxes++;
		} else
		{
			close (user->mailbox[i].fd);
			user->mailbox[i].fd = -1;
			if (LOG_LEVEL > 9) 
			{
				if (DEBUG)
				{
					fprintf(stderr, "Error: %s@%s:%d\n",user->username, user->mailbox[i].hostname, user->mailbox[i].port);
					perror ("Connecting to pop server");
				}
				syslog (LOG_NOTICE, "Error: %s@%s:%d : %m",user->username, user->mailbox[i].hostname, user->mailbox[i].port);	
			}
		}
	}

	if (!boxes)
	{
		// They didnt manage to log into anything
		if (LOG_LEVEL > 9)
		{
			if (DEBUG)
			{
				fprintf (stderr, "%s Invalid login\n", user->username);
			}
			syslog (LOG_NOTICE, "%s Invalid login\n", user->username);
		}
		return (-1);
	}

	return (0);
}


int	list_update_mailbox (userT *user, int box)
{
	// Does a LIST command, and updates the mailbox
	int	argc;
	char	argv0[MAX_ARG_LEN];
	char	argv1[MAX_ARG_LEN];
	char	argv2[MAX_ARG_LEN];
	int	num, i;
	int	r;
	messageT	message[MAX_MESSAGES];
	mailboxT	*mailbox = &user->mailbox[box];

	if (mailbox == NULL)
	{
		return (-1);
	}

	if (DEBUG)
	{
		snprintf (user->current_function, MAX_FUNC_LEN - 2, "list_update_mailbox (user, %d)", box);
	}

	if (mailbox->fd <=0 )
	{
		return (0);
	}

	num = 0;	
	send_pop (mailbox, "LIST");
	r=get_ok(mailbox);

	argv0[0] = '@';

	if (!r)
	{
		while (argv0[0] != '.')
		{
			argc=get_command (&mailbox->fd, argv0, argv1, argv2, argv2);

			if (argc < 0)
			{
				return (-1);
			}
			if (argc == 2)
			{
				if (num < MAX_MESSAGES-2)
				{	
					mailbox->messages++;
					mailbox->total_size += message[num].size = atol (argv1);
					message[num].deleted = 0;
					num++;
				}
			}
		}

		mailbox->message = (messageT *) malloc (sizeof(messageT) * mailbox->messages);	
		for (i = 0; i < num; i++)
		{
			mailbox->message[i].size = message[i].size;
			mailbox->message[i].deleted = message[i].deleted;
			mailbox->message[i].uidl[0] = 0;
		}

		mailbox->up_to_date = LIST_FLAG;
		return (0);
	}
	return (1);
}

int	uidl_update_mailbox (userT *user, int box)
{
	// Does a LIST command, and updates the mailbox
	int	argc;
	char	argv0[MAX_ARG_LEN];
	char	argv1[MAX_ARG_LEN];
	int	num;
	mailboxT	*mailbox = &user->mailbox[box];
	
	if (mailbox->fd <=0 )
	{
		return (0);
	}
	
	snprintf (user->current_function, MAX_FUNC_LEN - 2, "uidl_update_mailbox (user, %d)", box);

	send_pop (mailbox, "UIDL");
	argc = get_command (&mailbox->fd, argv0, argv1, argv1, argv1);

	if (argc == -1)
	{
		return (-1);
	}

	num = 0;
	if (argc && !strcmp (argv0, OK))
	{
		while (argv0[0] != '.')
		{
			argc=get_command (&mailbox->fd, argv0, argv1, argv0, argv0);

			if (argc == -1)
			{
				return (-1);
			}
			if (argc == 2)
			{
				if (num < MAX_MESSAGES-2)
				{	
					strncpy (mailbox->message[num++].uidl, argv1, MAX_UIDL-1);
				}
			}
		}

		mailbox->up_to_date = LIST_FLAG;
		return (0);
	}
	return (1);
}

int	list_update_mailboxes (userT *user)
{
	int	box;

	if (DEBUG)
	{
		snprintf (user->current_function, MAX_FUNC_LEN - 2, "list_update_mailboxes");
	}

	for (box = 0; box < user->mailboxes; box++)
	{
		if ((user->mailbox[box].fd > 0) && !(user->mailbox[box].up_to_date & LIST_FLAG))
		{
			if (list_update_mailbox (user, box) == -1)
			{
				return (-1);
			}
			if (uidl_update_mailbox (user, box) == -1)
			{
				return (-1);
			}
		} 
	}

	return (0);
}

int	get_box (userT *user, long *num)
{
	// Gets a message number and a user
	// Works out which mailbox this message is in
	// and returns the box number, and modifies *num
	// to have the value of the message number in
	// that box.
	// if the message is not in any box, it returns
	// -1.

	int	box;
	long 	anum;
	int	total, ptotal;

	anum = (*num);

	if (DEBUG)	
	{
		snprintf (user->current_function, MAX_FUNC_LEN - 2, "list_update_mailboxes (user, %ld)", *num);
	}

	list_update_mailboxes (user);

	total = ptotal = box = 0;

	while ((box < user->mailboxes) && (*num > total))
	{
		if (user->mailbox[box].fd > 0)
		{
			ptotal = total;
			total += user->mailbox[box].messages;
		}

		if (*num > total)
		{	
			box++;
		}
	}
	if (*num <= total) 
	{
		*num = *num - ptotal - 1;
		return (box);
	} else
	{
		return (-1);
	}
}	

int	status (userT *user, int box, long *messages, long *size)
{
	// Does a stat on a particular mailbox, return results
	// in messages and size

	int	argc;
	char	argv0[MAX_ARG_LEN];
	char	argv1[MAX_ARG_LEN];
	char	argv2[MAX_ARG_LEN];
	char	argv3[MAX_ARG_LEN];
	mailboxT	*mailbox = &user->mailbox[box];

	if (DEBUG)
	{
		snprintf (user->current_function, MAX_FUNC_LEN - 2, "stat (user, %d, %ld, %ld)", box, *messages, *size);
	}

	send_pop (mailbox, "STAT");
	argc=get_command (&mailbox->fd, argv0, argv1, argv2, argv3);

	if (argc == -1)
	{
		return (-1);
	}

	if ((argc == 3) && !strcmp (argv0, OK))
	{
		*messages += atol (argv1);
		*size += atol (argv2);
		return (0);
	} 

	return (1);
}


int	list (userT *user)
{
	// Does a list command on a particular mailbox,
	// but rewrites the message number so they all
	// look like one list.
	
	int	num, i, r;
	int	box;
	long	total, total_size;
	char	str[MAX_LINE];

	if (DEBUG)
	{
		snprintf (user->current_function, MAX_FUNC_LEN - 2, "list (user)");
	}

	num = 0;
	total = 0;
	total_size = 0;

	for (box = 0; box < user->mailboxes; box++)
	{
		if ((user->mailbox[box].fd > 0) && !(user->mailbox[box].up_to_date & LIST_FLAG))
		{
			if ((r = list_update_mailbox (user, box)))
			{
				return (r);
			}
			if (uidl_update_mailbox (user, box) == -1)
			{
				return (-1);
			}
		}
		if (user->mailbox[box].fd > 0)
		{
			int	m;
			for (m =0; m < user->mailbox[box].messages; m++)
			{
				if (!user->mailbox[box].message[m].deleted)
				{
					total += 1;
					total_size += user->mailbox[box].message[m].size;
				}
			}
		}
	}

	snprintf (str, MAX_LINE-1, "%ld messages (%ld octets)", total, total_size);
	ok (user->fd, str);
	
	for (box = 0; box < user->mailboxes; box++)
	{
		if (user->mailbox[box].fd > 0)
		{
			for (i=0; i < user->mailbox[box].messages; i++)
			{
				num++;
				if (!user->mailbox[box].message[i].deleted)
				{
					snprintf (str, MAX_LINE-1, "%d %ld", num, user->mailbox[box].message[i].size);
					to_client (user->fd, str);
				}
			}
		}
	}

	to_client (user->fd, ".");	

	return (0);
}

int	list_s (userT *user, long num)
{
	// Does a list on a single message

	int	box;
	long	anum;
	char	str[MAX_LINE];

	if (DEBUG)
	{
		snprintf (user->current_function, MAX_FUNC_LEN - 2, "list_s (user, %ld)", num);
	}

	anum = num;
	box = 0;

	if ( (box = get_box (user, &num)) == -1)
	{
		err (user, "No such message");

		return (0);
	}

	if (!user->mailbox[box].message[num].deleted)
	{
		snprintf (str, MAX_LINE-1, "%ld %ld", anum, user->mailbox[box].message[num].size);

		ok (user->fd, str);

	} else
	{
		err (user, "No such message");
	}

	return (0);
}

int	uidl (userT *user)
{
	// Does a uidl command on a particular mailbox,
	// but reabfabs the message number so they all
	// look like one list.
	
	int	num, i;
	int	box;
	char	str[MAX_LINE];

	if (DEBUG)
	{
		snprintf (user->current_function, MAX_FUNC_LEN - 2, "uidl (user)");
	}

	num = 0;

	// Need to ensure a good list to have a good uidl!
	if (list_update_mailboxes (user) == -1)
	{
		return (-1);
	}

	ok (user->fd, "UIDL List");
	
	for (box = 0; box < user->mailboxes; box++)
	{
		if (user->mailbox[box].fd > 0)
		{
			for (i=0; i < user->mailbox[box].messages; i++)
			{
				num++;
				if (!user->mailbox[box].message[i].deleted)
				{

					if (SMUNGE_UIDL > 0)
					{
						char	smunged_uidl[MAX_UIDL-1];
					
						snprintf (smunged_uidl, MAX_UIDL-1, "%s%s", user->mailbox[box].uidl_hash, user->mailbox[box].message[i].uidl);
						snprintf (str, MAX_LINE - 1, "%d %s", num, smunged_uidl);
					} else
					{
						snprintf (str, MAX_LINE-1, "%d %s", num, user->mailbox[box].message[i].uidl);
					}
					to_client (user->fd, str);

				}
			}
		}
	}
	
	to_client (user->fd, ".");

	return (0);
}

int	uidl_s (userT *user, long num)
{
	// Does a uidl on a single message

	int	box;
	long	anum;
	char	str[MAX_LINE];

	if (DEBUG)
	{
		snprintf (user->current_function, MAX_FUNC_LEN - 2, "uidl_s (user, %ld)", num);
	}

	if (list_update_mailboxes (user) == -1)
	{
		err (user, "Fatal error: uidl_s");

		return (-1);
	}

	anum = num;
	if ((box = get_box(user, &num)) == -1)
	{
		err (user, "No such message");

		return (0);
	}

	if ((box < user->mailboxes) && 
	    (!user->mailbox[box].message[num].deleted))
	{
		snprintf (str, MAX_LINE-1, "%ld %s", anum, user->mailbox[box].message[num].uidl);
		ok (user->fd, str);
	} else
	{
		err (user, "No such message");
	}

	return (0);
}

int	buffy (userT *user, int box, char *buf)
{
	int		r;
	
	if (DEBUG)
	{
		snprintf (user->current_function, MAX_FUNC_LEN - 2, "buffy (user, %d, %p)", box, buf);
	}

	r = read(user->mailbox[box].fd, buf, MAX_LINE-1);

	return (r);
}
		
int	retr (userT *user, long num, long lines)
{
	// Returns the contents of a single message

	int	box;
	char	str[MAX_LINE];
	char	buf[MAX_LINE];
	int 	state = 0, len = strlen(CRLFDOTCRLF);
	int	r, i, seglen;

	if (DEBUG)
	{
		snprintf (user->current_function, MAX_FUNC_LEN - 2, "retr (user, %ld, %ld)", num, lines);
	}

	if (list_update_mailboxes (user) == -1)
	{	
		err (user, "Fatal error: retr");

		return (-1);
	}

	if (num <= 0)
	{
		err (user, "No such message");

		return (0);
	}
	if ( (box = get_box (user, &num)) == -1)
	{
		err (user, "No such message");

		return (0);
	}
	// Now do the return to the appropriate box, and foward the
	// crap

	if (lines < 0)
	{
		snprintf (str, MAX_LINE-1, "RETR %ld", num + 1);

		send_pop (&user->mailbox[box], str);
	} else	
	{
		snprintf (str, MAX_LINE-1, "TOP %ld %ld", num + 1, lines);

		send_pop (&user->mailbox[box], str);
	}

	while( (r=buffy (user, box, buf))  > 0)
	{
		user->time = time(NULL);
		seglen = 0;
		for (i = 0; (i < r) && (state != len); i++)
		{
			if(buf[i] != *(CRLFDOTCRLF + state)) 
			{
				state = 0;
			} 
			if(buf[i] == *(CRLFDOTCRLF + state)) 
			{
				state++;
			} 

			seglen++;
		}

		// Write the appropriate part of the buffy
		abfab (user->fd, buf, seglen);

		if(state == len)
			break;
	}

	if ((state != len)&&(lines))
	{
		terminate (user->fd);
	}

	return (0);
}

	
int	dele (userT *user, long num)
{
	// Deletes a single message

	int	box;
	long	anum;
	char	str[MAX_LINE];
	int	argc;
	char	argv0[MAX_ARG_LEN];
	char	argv1[MAX_ARG_LEN];

	if (DEBUG)
	{
		snprintf (user->current_function, MAX_FUNC_LEN - 2, "dele (user, %ld)", num);
	}

	anum = num;
	box = 0;

	if ( (box = get_box (user, &num)) == -1)
	{
		err (user, "No such message");
		return (0);
	}

	snprintf (str, MAX_LINE-1, "DELE %ld", num + 1);

	send_pop (&user->mailbox[box], str);
	argc=get_command (&user->mailbox[box].fd, argv0, argv1, argv1, argv1);

	if (argc == -1)
	{
		return (-1);
	}
	if (argc && !strcmp (argv0, OK))
	{		
		user->mailbox[box].message[num].deleted = 1;
		snprintf (str, MAX_LINE-1, "Message %ld deleted", anum);
		ok (user->fd, str);
	} else
	{
		err (user, "Couldnt delete");
	}
	
	return (0);	
}	
	
int	rset (userT *user)
{
	int	i;
	int	box;
	int	del, total;
	char	str[MAX_LINE];

	if (DEBUG)
	{
		snprintf (user->current_function, MAX_FUNC_LEN - 2, "rset (user)");
	}

	total = del = 0;
	for (box = 0; box < user->mailboxes; box++)
	{
		send_pop (&user->mailbox[box], "RSET");
		get_ok (&user->mailbox[box]);

		for (i = 0; i < user->mailbox[box].messages; i++)
		{
			if (user->mailbox[box].message[i].deleted)
			{
				del++;
			}
			user->mailbox[box].message[i].deleted = 0;	
			total++;
		}
	}
	snprintf (str, MAX_LINE-1, "%d undeleted, of %d total", del, total);	

	ok (user->fd, str);

	return (0);
}

int	quit (userT *user)
{
	int	box;

	if (DEBUG)
	{
		snprintf (user->current_function, MAX_FUNC_LEN - 2, "dbug (user)");
	}

	for (box = 0; box < user->mailboxes; box++)
	{
		send_pop (&user->mailbox[box], "QUIT");
		get_ok (&user->mailbox[box]);
	}

	return (0);
}

int	debug (userT *user)
{
	// Used for printing all a users data for debugging 
	// purposes.

	int	box;
	long	num;
	int	fd;
	char	str[MAX_LINE];

	fd = user->fd;	

	snprintf (str, MAX_LINE-1, "Debug info for %s (%s) on fd:%d", user->username, user->password, fd);
	to_client (fd, str);		

	snprintf (str, MAX_LINE-1, "Errors %d of %d", user->errors, MAX_ERRORS);
	to_client (fd, str);
	snprintf (str, MAX_LINE-1, "Mailboxes : %d total.", user->mailboxes);
	to_client (fd, str);

	for (box = 0; box < user->mailboxes; box++)
	{
		snprintf (str, MAX_LINE-1, "\tMailbox %d (%ld messages, totalling  %ld octets) (host:%d fd:%d):", box, user->mailbox[box].messages, user->mailbox[box].total_size,
					user->mailbox[box].port,
					user->mailbox[box].fd);
		to_client (fd, str);
		for (num = 0; num < user->mailbox[box].messages; num++)
		{
			snprintf (str, MAX_LINE-1, "\t\t(%d)%ld - %ld bytes, [%s]",
				user->mailbox[box].message[num].deleted,num,
				user->mailbox[box].message[num].size,
				user->mailbox[box].message[num].uidl);
			to_client (fd, str);
		}
	}	
	return (0);
}
