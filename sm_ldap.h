#ifdef USE_LDAP

#ifndef SM_LDAP_H
#define SM_LDAP_H

#define MAX_FILTER		256
#define MAX_LDAP_POPS		16
#define MAX_LDAP_POP_LEN 	32

char *ldap_auth_err_codes[6];

int	ldap_auth (const char *username, char *passwd, char **pop_hosts);

#endif

#endif
