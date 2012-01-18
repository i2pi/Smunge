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
#include <signal.h>
#include <unistd.h>
#include <ctype.h>
#ifdef SOLARIS
#include <strings.h>
#else
#include <string.h>
#endif
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <syslog.h>

#include "server.h"
#include "mail.h"
#include "config.h"

void	*Signal (int signo, void (*func)(int))
{
	// A wrapper to sigaction, with SA_RESTART
	// for interupted system calls

	struct sigaction	act, oact;
	
	act.sa_handler = func;
	sigemptyset (&act.sa_mask);
	act.sa_flags = 0;
	if (signo == SIGALRM)
	{
		act.sa_flags |= SA_RESTART;
	}

	if (sigaction (signo, &act, &oact) < 0)
	{
		return (SIG_ERR);
	}

	return (oact.sa_handler);
}

void	sig_chld (int signo)
{
	int	stat;

	while (waitpid (-1, &stat, WNOHANG) > 0);	
	return;
}

void	usage (char *name)
{
	printf ("%s [options] +host:[port][,pattern[,pattern]...] [[+host:[port][,pattern[...]]] ... ]\n", name);
	printf ("Options :\n\t-p port \t: specify port to run on (default: 110)\n\t-d [level] \t: turn on debugging (disbaled)\n");
	printf ("\t-v \t\t: turn on verbose echoing of syslogs\n");
	printf ("\t-t sec \t\t: set the idle timeout (600)\n");
	printf ("\t-e num \t\t: set the maximum pop errors before a client is rejected (100)\n");
#ifdef USE_DRAC
	printf ("\t-D [drac host]\t: enable DRAC authentication (disabled)\n");
#endif
#ifdef USE_LDAP
	printf ("\t-h host[:port] :specify LDAP host (defaults to localhost:389)\n");
	printf ("\t-b basedn\t:specify LDAP basedn\n");
	printf ("\t-L [filter] \t: force LDAP authentication, and set username filter (filter defaults to '(uid=%s)')\n","%s");
	printf ("\t-P [pop field] \t: search LDAP for specific pop servers per user (defaults to 'popserver')\n");
#endif
	printf ("\t-U \t\t:prepend a hash of pop hostname before uidl's returned by that server\n");
	printf ("\t-s [username]\t: set effective uid to that of username when forking (nobody)\n");
}

int	isnumstr (char *str)
{
	int	i;

	if (str[0] == '-')
	{
		return (0);
	}

	for (i = 0; i < strlen (str); i++)
	{
		if (!isdigit(str[(int)i]))
		{
			return (0);
		}
	}

	return (1);
}

int	isalstr (char *str)
{
	int	i;

	if (str[0] == '-')
	{
		return (0);
	}

	for (i = 0; i < strlen (str); i++)
	{
		if (!isalpha(str[i]))
		{
			return (0);
		}
	}

	return (1);
}

void	init_popservers (void)
{
	int	i, p;

	for (i = 0; i < MAX_POPSERVERS; i++)
	{
		popserver[i].hostname[0] = '\0';
		popserver[i].host = NULL;
		for (p = 0; p < MAX_PATTERNS; p++)
		{
			popserver[i].pattern[p] = NULL;
		}
	}
}

int	get_free_popserver (void)
{
	int	i = 0;

	while ((i < MAX_POPSERVERS) && (popserver[i].host != NULL))
	{
		i++;
	}

	if (i >= MAX_POPSERVERS)
	{
		return (-1);
	}

	return (i);
}

int	add_popserver (char *hostname)
{
	int	num;
#ifndef FREEBSD
	int	errn;
#endif

	num = get_free_popserver ();

	if (num < 0)
	{
		return -1;
	}

	strncpy (popserver[num].hostname, hostname, MAX_HOSTNAME-1);

	popserver[num].host = (struct hostent *) malloc (sizeof (struct hostent)+1);

	if (popserver[num].host == NULL)
	{
		perror ("malloc");
		exit (-1);
	}

#ifdef SOLARIS
	gethostbyname_r (hostname, popserver[num].host, popserver[num].hostbuf, HOSTBUF_LEN, &errn);
#endif

#ifdef LINUX
	gethostbyname_r (hostname, popserver[num].host, popserver[num].hostbuf, (size_t) HOSTBUF_LEN, &popserver[num].host, &errn);
#endif
	
#ifdef FREEBSD
	popserver[num].host = gethostbyname (hostname);
#endif

	printf ("%s looked up as %s\n", hostname, popserver[num].host->h_name);

	if (popserver[num].host == NULL)
	{
		fprintf (stderr, "adding popserver '%s':\n", hostname);
		perror ("gethostbyname");
		exit (-1);
	}

	return (num);
}

int	add_popserver_pattern (int num, char *pattern)
{
	int	i;

	i = 0;

	while ((i < MAX_PATTERNS) && (popserver[num].pattern[i] != NULL))
	{
		i++;
	}

	if (i >= MAX_PATTERNS)
	{
		return (-1);
	} 

	popserver[num].pattern[i] = strdup (pattern);

	return (i);
}

int	daemonize (void)
{
	pid_t	pid;
	
	if ( (pid = fork ()) < 0)
	{
		// Failed to fork!
	
		return (-1);
	} else 
	if (pid != 0)
	{
		// We are the parent. and parents suck
		// so kill your parent!!
		
		exit (0);
	}
	
	setsid ();
	chdir ("/");
	umask (0);
	
	return (0);
}
		

int	main (int argc, char **argv)
{
	int	i;

	// Put that in your pipe, and smoke it!
	Signal (SIGPIPE, SIG_IGN);
	Signal (SIGCHLD, sig_chld);
	

	if (argc < 2)
	{
		usage (argv[0]);
		exit (1);
	}

	// Default values

	PORT=110;
	DEBUG=0;
	LOG_LEVEL=11;
	HOSTFILE[0] = '\0';
	MAX_IDLE=500;
	MAX_ERRORS=100;
	DRAC_AUTH=0;
	DRAC_HOST=NULL;
	EUID=0;	
	EGID=0;
	SM_LDAP_HOST = NULL;
	SM_LDAP_PORT = 389;
	SM_LDAP_BASEDN = NULL;
	USER_FILTER = NULL;
	SMUNGE_UIDL = 0;

	init_popservers ();

	// Command line options :
	// p port	Specify the server port
	// d [level]	Set debugging mode and level
	// t sec	set the idle timout
	// e num	set the error threshold
	// D [host]	enable DRAC auth - providing a host will override the assumption
	//		that each pop server is running dracd
	// s [username]	set euid when forking
	// h host[:port]		specify ldap host:port
	// b basedn	specify ldap basedn
	// L user_filter	force LDAP auth with user_filter	
	// U 		smunge UIDLs, ie. prepend a hash of hostname in the uidl field

	i = 0;
	while (++i < argc)
	{
		if (argv[i][0] == '-')
		{
			// we have an option
			switch (argv[i][1])
			{
				case 'v':
				{
					DEBUG = 1;
				} break;
				case 'p': 
				{
					if ((i+1 < argc) && (isnumstr (argv[i+1])))
					{
						PORT = atol (argv[i+1]);
						i++;
					} else
					{
						usage (argv[0]);
						exit (1);
					}
				} break;
				case 'd':
				{
					if ((i+1 < argc) && (isnumstr (argv[i+1])))
					{
						LOG_LEVEL = atol (argv[i+1]);
						i++;	
					} else
					{
						LOG_LEVEL=10;
					}
				} break;
				case 's': 
				{
					struct	passwd	*pass;

					if ((i+1 < argc) && (isalstr (argv[i+1])))
					{
						pass = getpwnam (argv[i+1]);						
						EUID = pass->pw_uid;
						EGID = pass->pw_gid;
						i++;
					}
				} break;
				case 't': 
				{
					if ((i+1 < argc) && (isnumstr (argv[i+1])))
					{
						MAX_IDLE = atol (argv[i+1]);
						i++;
					} else
					{
						usage (argv[0]);
						exit (1);
					}
				} break;
				case 'e':
				{
					if ((i+1 < argc) && (isnumstr (argv[i+1])))
					{
						MAX_ERRORS = atol (argv[i+1]);
						i++;
					} else
					{
						usage (argv[0]);
						exit (1);
					}
				} break;
#ifdef USE_DRAC
				case 'D':
				{
					DRAC_AUTH = 1;

					if ( (i+1 < argc) && ( (argv[i+1][0] != '-') && (argv[i+1][0] != '+') ))
					{
						DRAC_HOST = strdup (argv[i+1]);
						i++;
					}
				} break;
#endif
#ifdef USE_LDAP	
				case 'h':
				{
					char	*p;

					if ((i+1 < argc) && (((argv[i+1][0])!='-') && (argv[i+1][0] != '+')) )
					{
						if (!SM_LDAP_HOST)
						{
							free (SM_LDAP_HOST);
						}
						SM_LDAP_HOST=strdup (strtok (argv[i+1], ":"));
						if ( (p = strtok (NULL, ":")) )
						{
							SM_LDAP_PORT = atol (p);
						}	
						i++;
					} else
					{
						usage (argv[0]);
						exit (1);
					}
				} break;
				case 'b':
				{
					if ((i+1 < argc) && (((argv[i+1][0])!='-') && (argv[i+1][0] != '+')) )
					{
						if (!SM_LDAP_BASEDN)
						{
							free (SM_LDAP_BASEDN);
						}
						SM_LDAP_BASEDN = strdup (argv[i+1]);
						i++;
					} else
					{
						usage (argv[0]);
						exit (1);
					}
				} break;
				case 'P':
				{
					if ((i+1 < argc) && (isalpha(argv[i+1][0])))
					{
						if (!SM_LDAP_POP)
						{
							free (SM_LDAP_POP);
						}
						SM_LDAP_POP = strdup (argv[i+1]);
						i++;
					} else
					{
						if (!SM_LDAP_POP)
						{
							free (SM_LDAP_POP);
						}
						SM_LDAP_POP = strdup ("popserver");
					}
				} break;
				case 'L':
				{
					if ((i+1 < argc) && (isalpha(argv[i+1][0])))
					{
						if (!USER_FILTER)
						{
							free (USER_FILTER);
						}
						USER_FILTER = strdup (argv[i+1]);
						i++;
					} else
					{
						USER_FILTER = strdup ("(uid=%s)");
					}
						
					SM_LDAP_AUTH = 1;
				} break;	
#endif
				case 'U':
				{
					SMUNGE_UIDL = 1;
				} break;
				default:
				{
					usage (argv[0]);
					exit (1);
				} break;
			}
		} else
		if (argv[i][0] == '+')
		{
			// We are adding a host
			char	hostname[MAX_HOSTNAME];
			char	str[MAX_HOSTNAME];
			char	*t;
			char	*pat;
			int	serv_num;

			strncpy (str, &argv[i][1], MAX_HOSTNAME-1);
			strncpy (hostname, strtok (str, ":,"), MAX_HOSTNAME-1);
			strncpy (str, &argv[i][1], MAX_HOSTNAME-1);
			

			if ( (serv_num = add_popserver (hostname)) < 0 )
			{
				fprintf (stderr, "Error adding popserver '%s'\n", hostname);
				exit (-1);
			}

			if ( (t = strchr (str, ':')) )
			{
				popserver[serv_num].port = atol (t+1);
			} else
			{
				popserver[serv_num].port = 110;
			}

			if ( (t = strchr (str, ',')) )
			{
				// We have a pattern rule(s) for this popserver	
			
				pat = strdup (strtok (t+1, ",\n\r"));
				add_popserver_pattern (serv_num, pat);
			
				while ( (pat = strtok (NULL, ",\n\r")) != NULL)
				{
					if (add_popserver_pattern (serv_num, pat) < 0)
					{
						fprintf (stderr, "Error adding rule '%s' for popserver '%s'\n", pat, hostname);
						exit (-1);
					}
				}
			} 
				
	
			printf ("Added popserver %s:%d\n", hostname, popserver[serv_num].port);
			if (popserver[serv_num].pattern[0] != NULL)
			{
				int i = 0;

				while ((i < MAX_PATTERNS) && (popserver[serv_num].pattern[i]))
				{
					printf ("\tPattern rule %d : '%s'\n", i, popserver[serv_num].pattern[i]);
					i++;
				}
			}
	
		} else
		{
			usage (argv[0]);
			exit (1);
		}
	}

#ifdef USE_LDAP	
	if (!SM_LDAP_HOST)
	{
		SM_LDAP_HOST=strdup ("localhost");
	}
	if (!USER_FILTER)
	{
		USER_FILTER=strdup ("(uid=%s)");
	}
#endif
		
	if (!EUID)
	{	
		struct passwd *pass;			
		pass = getpwnam ("nobody");						

		if (pass == NULL)
		{
			fprintf (stderr, "Couldn't getpwnam for 'nobody'!!\n");
			exit (-1);
		}

		EUID = pass->pw_uid;
		EGID = pass->pw_gid;
	}

	// Opening syslog
	openlog ("smunged", LOG_PID, LOG_MAIL);


	// Become a child of the devil
	printf ("Becoming a daemon....\n");
	if (daemonize ())
	{
		fprintf (stderr, "Failed to daemonize!\n");
		exit (-1);
	}

	printf ("Return : %d\n", start_server());

	return (0);
}
