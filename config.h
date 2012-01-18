#ifndef CONFIG_H
#define CONFIG_H

#include <sys/types.h>
#include <pwd.h>

#define MAX_HOST_FILE_PATH	256

extern int 	PORT;
extern int 	DEBUG;
extern int 	LOG_LEVEL;
extern char 	HOSTFILE[MAX_HOST_FILE_PATH];
extern int	MAX_IDLE;
extern int	MAX_ERRORS;
extern int	DRAC_AUTH;
extern char	*DRAC_HOST;
extern uid_t	EUID;
extern gid_t	EGID;
extern char	*SM_LDAP_HOST;
extern int	SM_LDAP_PORT;
extern char	*SM_LDAP_BASEDN;
extern char	*USER_FILTER;
extern char	SM_LDAP_AUTH;
extern char	*SM_LDAP_POP;
extern char	SMUNGE_UIDL;

#endif
