PAM_LIB_DIR = $(DESTDIR)/lib64/security
CC = gcc
LD = ld
INSTALL = /usr/bin/install
CFLAGS = -fPIC -O2 -c -g -Wall -Wformat-security -fno-strict-aliasing
LDFLAGS = --shared --build-id
PAMLIB = -lpam

all: pam_rbld.so

pam_rbld.so: pam_rbld.o
	$(LD) $(LDFLAGS) -o pam_rbld.so pam_rbld.o $(PAMLIB)

pam_rbld.o: pam_rbld.c
	$(CC) $(CFLAGS) pam_rbld.c

install: pam_rbld.so
	$(INSTALL) -m 0755 -d $(PAM_LIB_DIR)
	$(INSTALL) -m 0755 pam_rbld.so $(PAM_LIB_DIR)

clean:
	rm -f pam_rbld.o pam_rbld.so
