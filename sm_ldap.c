#ifdef USE_LDAP

#include <lber.h>
#include <ldap.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>

#include "config.h"
#include "sm_ldap.h"

char *ldap_auth_err_codes[6] = 
{
	"OK",
	"Failed to open",
	"Search failed",
	"Failed to get dn",
	"Bind failed",
	"Auth bind failed"
};

int	ldap_auth (const char *username, char *passwd, char **pop_hosts)
{	

	/* Authenticates username against ldap by using the USER_FILTER
	   to find their DN, and attempting to bind to that DN with the
	   supplied passwd.
	   
	   If pop_hosts != NULL, then it will fill it with the users
	   listed mailbox hosts. (to a maximum number of MAX_LDAP_POPS)

	   Returns < 0 for failure, 0 for success or >0 for the number of
	   pop hosts
	*/

	LDAP			*myLDAP;
	LDAPMessage		*result;
	char			*dn;
	char			filter[128];
	char			**value;

	myLDAP = ldap_open (SM_LDAP_HOST, SM_LDAP_PORT);

	if (myLDAP == NULL)
	{
		return (1);
	} 


	if (ldap_simple_bind_s (myLDAP, "", "") != LDAP_SUCCESS)
	{	
		return (2);
	} 

	snprintf (filter, MAX_FILTER, USER_FILTER, username);

	if (ldap_search_s (myLDAP, SM_LDAP_BASEDN, LDAP_SCOPE_SUBTREE, filter, NULL, 0, &result) != LDAP_SUCCESS)
	{
		return (3);
	}

	dn = ldap_get_dn (myLDAP, result);
	
	if (!dn)
	{
		return (4);
	} else
	if (SM_LDAP_AUTH)
	{
		if (ldap_simple_bind_s (myLDAP, dn, passwd) != LDAP_SUCCESS)
		{
			return (5);
		}
	}
	
	// We are authenticated!
	// 


	if (pop_hosts == NULL)
	{
		ldap_unbind (myLDAP);
		return (0);
	}
	
	
	// Need to find the LDAP listed pop servers, if any

	value = ldap_get_values (myLDAP, result, SM_LDAP_POP);
	
	if (value)
	{
		// There are some pop servers listed
	
		int	i;

		i = 0;	

		while (value[i] && (i < MAX_LDAP_POPS))	
		{
			pop_hosts[i] = strdup (value[i]);
			if (LOG_LEVEL > 40)
			{
				if (DEBUG)
				{
					fprintf (stderr, "Adding popserver %s for %s from LDAP\n", pop_hosts[i], username);
				}
				syslog (LOG_NOTICE, "Adding popserver %s for %s from LDAP\n", pop_hosts[i], username);
			}
			i++;
		}
		return (i);
	}
	
	return (0);
}

#endif
