#
# Makefile for smunged
#
# Been tested on 	Solaris 2.6/7 (SPARC/Intel)
# 			FreeBSD 3.3/3.4 (Intel)
#			RedHat Linux 6.2 (Intel)
#
# To build for your platform just uncomment the 
# appropriate section below :
#

# Solaris
#
#CFLAGS= -Wall -O3 -DSOLARIS 
#LDFLAGS= -lxnet -lnsl -lposix4 

# FreeBSD
#
#CFLAGS= -Wall -O3 -DFREEBSD -DUSE_LDAP -I/usr/local/include
#LDFLAGS= -L/usr/local/lib -lldap -llber

# Linux
#
CFLAGS= -Wall -O3  #-DLINUX -DUSE_LDAP
LDFLAGS=  #-lldap -llber

########################################################################################


CC = gcc
LD = gcc

SMUNGE = smunged
SRCS = config.c main.c server.c mail.c smunge.c sm_ldap.c
OBJS = config.o main.o server.o mail.o smunge.o sm_ldap.o

$(SMUNGE): $(OBJS)
	$(CC) $(CFLAGS) -o $(SMUNGE) $(OBJS) $(LDFLAGS) 

install:
	install smunged /usr/local/sbin/smunged

clean :
	-rm -f *.o core core.smunged smunged

