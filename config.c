/*******************************************
   Smunge. 

   POP-3 Funnelling Proxy.

   Distributed under the terms of the
   GNU General Public License.

   See LICENSE File for license details.

   Copyright (c) Joshua Reich 2000
   http://www.i2pi.com/smunge/
********************************************/


#include "config.h"
#include <stdio.h>

int 	PORT = 110;
int 	DEBUG = 0;
int 	LOG_LEVEL = 10;
char 	HOSTFILE[MAX_HOST_FILE_PATH];
int	MAX_IDLE = 600;
int	MAX_ERRORS = 100;
int	DRAC_AUTH = 0;
char	*DRAC_HOST = NULL;
uid_t	EUID;
gid_t	EGID;
char	*SM_LDAP_HOST=NULL;
int	SM_LDAP_PORT=389;
char	*SM_LDAP_BASEDN=NULL;
char	*USER_FILTER=NULL;
char	SM_LDAP_AUTH=0;
char	*SM_LDAP_POP=NULL;
char	SMUNGE_UIDL=0;

