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
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "mail.h"
#include "server.h"
#include "config.h"

int	smunge (userT *user)
{
	// Interactively deals with users pop commands,
	// servicing them from the users pop servers,
	// smunging the results as needed.

	int	argc;
	char	argv0[MAX_ARG_LEN];
	char	argv1[MAX_ARG_LEN];
	char	argv2[MAX_ARG_LEN];
	char	argv3[MAX_ARG_LEN];
	int	i;
	char	response[MAX_LINE];

	if (!user || (user->fd < 1))
	{
		return -1;
	}

	while (user->fd > 0)
	{
		watchdog (user);
		if (user->fd < 0)
		{
			return (-1);
		}
		
		argc=get_command (&user->fd, argv0, argv1, argv2, argv3);
 
		if (argc < 0)
		{
			// there was a problem.
			return (0);
		} else
		if (argc)
		{
			if (!strcmp (argv0, "QUIT"))
			{ 
				quit (user);
				ok (user->fd, "Have a nice day");	
				return (0);
			} else
			if (!strcmp (argv0, "DBUG") && (LOG_LEVEL==666))
			{
				debug (user);
			} else
			if (!strcmp (argv0, "STAT"))
			{
				long messages = 0;
				long size = 0;

				user->time = time(NULL);
				for (i=0; i < user->mailboxes; i++)
				{
					if (user->mailbox[i].fd > 0)
					{
						if (status (user, i, &messages, &size) == -1)
						{
							return (0);
						}
					}
				}
				snprintf (response, MAX_LINE-1, "%ld %ld", messages, size);

				ok (user->fd, response);
			} else
			if (!strcmp (argv0, "LIST"))
			{
				user->time = time(NULL);
				// if given with no arguments
				if (argc == 1)
				{
					if (list (user) == -1)
					{
						return (0);
					}
				} else
				{
					if (list_s (user, atol(argv1)) == -1)
					{
						return (0);
					}
				}
			} else
			if (!strcmp (argv0, "UIDL"))
			{
				user->time = time(NULL);
				// if given with no arguments
				if (argc == 1)
				{
					if (uidl (user) == -1)
					{
						return (0);
					}
				} else
				{
					if (uidl_s (user, atol(argv1)) == -1)
					{
						return (0);
					}
				}
			} else
			if ((argc == 2) && (!strcmp (argv0, "RETR")))
			{
				user->time = time(NULL);
				if (retr (user, atol(argv1), -1) == -1)
				{
					return (0);
				}
			} else
			if ((argc == 2) && (!strcmp (argv0, "DELE")))
			{
				user->time = time(NULL);
				if (dele (user, atol(argv1)) == -1)
				{
					return (0);
				}	
			} else
			if ((argc == 3) && (!strcmp (argv0, "TOP")))
			{
				user->time = time(NULL);

				if (atol(argv2) < 0)
				{
					err (user, "Need to supply a non-negative number of lines");
				} else
				if (retr (user, atol(argv1), atol(argv2)) == -1)
				{
					return (0);
				}
			} else
			if (!strcmp (argv0, "RSET"))
			{
				user->time = time(NULL);
				if (rset (user) == -1)
				{
					return (0);
				}
			} else
			if (!strcmp (argv0, "NOOP"))
			{
				user->time = time(NULL);
				ok (user->fd, "Keeping out of trouble");
			} else
			{
				user->time = time(NULL);
				snprintf (response, MAX_LINE-1, "Invalid commmand - %s", argv0);
				err (user, response); 
			}
		
		} else
		{
			user->time = time(NULL);
			err (user, "Talk to me");
		}
	}

	return (0);
}
