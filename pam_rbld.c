/*************************************************************************
* pam_rbld - PAM module for interacting with rbld
* Copyright 2006 - 2014, Bluehost, Inc.
*
* Authors and Contributers:
*
* Erick Cantwell    <ecantwell@bluehost.com>
*
* http://www.bluehost.com
* https://github.com/bluehost/pam_rbld
*
**************************************************************************
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA02111-1307, USA.
*
*************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

/* These guys all have to be here */
PAM_EXTERN int pam_sm_cred(pam_handle_t *pamh, int flags,int argc, const char **argv)
{
    return(PAM_SUCCESS);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,int argc, const char **argv)
{
    return(PAM_SUCCESS);
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return(PAM_SUCCESS);
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return(PAM_SUCCESS);
}

/* Dovecot requires that this not return success */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    /* This is basically only for Dovecot, since it insists on going through the motions */
    return(PAM_SUCCESS);
}

/* This is where we are actually functioning, in the authentication stage */

/* 
 * Dovecot isn't awesome at configuration and passdb chains as far as how we want 
 * to deny users. It's easy when they are in rbld, but not when they aren't.  So,
 * we are basically going to say "We don't know who you are talking about" if the
 * service is Dovecot so that it will move on to the next authentication method,
 * which is, in our specific caase, the cPanel script.  This goes for both 
 * returning when rbld is down and when we return our final value at the end.
 * If the service is not Dovecot, then we simply do the right thing and return
 * PAM_AUTH_SUCCESS.
 *
 * Keep in mind that we can only do this once we know the service, so we get that
 * pretty early on.
 */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,int argc, const char **argv)
{
    int debug = 0;

    /* If we have multiple arguments and argv[2] is "debug", then we turn on debugging output */
    if ((argc > 2) && (!strcmp(argv[2], "debug"))) {
        debug = 1;
        openlog("RBLD PAM DEBUGGING", LOG_PID, LOG_AUTHPRIV);
        syslog(LOG_INFO, "Number of args: %d", argc);
        syslog(LOG_INFO, "argv[0]: %s, argv[1]: %s, argv[2]: %s", argv[0], argv[1], argv[2]);
    /* If we have more than the required two arguments, and argument 3 is not debug, then it's misconfigured */
    } else if ((argc > 2) && (strcmp(argv[2], "debug"))) {
        openlog("pam_rbld", LOG_PID, LOG_AUTHPRIV);
        syslog(LOG_INFO, "%s is not a valid argument.  Only \"debug\" is allowed", argv[2]);
        closelog();
        return(PAM_SUCCESS);
    /* If we have less than two arguments, then we are incorrectly configured */
    } else if (argc < 2) {
        openlog("pam_rbld", LOG_PID, LOG_AUTHPRIV);
        syslog(LOG_INFO, "Incorrectly configured!  Should be <querylist> <socketpath> <debug>");
        return(PAM_SUCCESS);
    /* Finally, we can open up the log normally */
    } else {
        openlog("pam_rbld", LOG_PID, LOG_AUTHPRIV);
    }

    /* return values for getting the host and service */
    int hostretval;
    int serviceretval;

    /* The variables that will actually contain the host and service data */
    const char* pHost = NULL;
    const char* pService = NULL;

    hostretval = pam_get_item(pamh, PAM_RHOST, (const void **) &pHost);
    serviceretval = pam_get_item(pamh, PAM_SERVICE, (const void **) &pService);

    /* We need to bail if we got bad return codes */
    if (serviceretval != PAM_SUCCESS) {
        syslog(LOG_INFO, "pam_get_item returned %d while getting the service", serviceretval);
        closelog();
        return(PAM_SUCCESS);
    }

    if (hostretval != PAM_SUCCESS) {
        syslog(LOG_INFO, "pam_get_item returned %d while getting the IP address to check", hostretval);
        closelog();
        if (!strcmp(pService, "dovecot")) {
            return(PAM_USER_UNKNOWN);
        } else {
            return(PAM_SUCCESS);
        }
    }

    /* Next, we have to check if rhost is null, which according to the man page can happen */
    if (pHost == NULL) {
        syslog(LOG_INFO, "PAM_RHOST is NULL, can't continue");
        closelog();
        if (!strcmp(pService, "dovecot")) {
            return(PAM_USER_UNKNOWN);
        } else {
            return(PAM_SUCCESS);
        }
    }

    /* Validate if PAM_RHOST is an ip address, since I'm too lazy to look at the rbld code to see if it alread does this */
    /* This will probably be handy for when we need IPv6 support, too */
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, pHost, &(sa.sin_addr));

    if (!result) {
        syslog(LOG_INFO, "PAM_RHOST is not an IP address, can't continue");
        syslog(LOG_INFO, "PAM_RHOST: %s", pHost);
        closelog();
        if (!strcmp(pService, "dovecot")) {
            return(PAM_USER_UNKNOWN);
        } else {
            return(PAM_SUCCESS);
        }
    }

    /* Now that we have our values we need to connect to rbld */
    struct sockaddr_un rbld_sock;
    int  socket_fd, n;

    socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if(socket_fd < 0) {
        syslog(LOG_INFO, "socket() failed");
        if (!strcmp(pService, "dovecot")) {
            return(PAM_USER_UNKNOWN);
        } else {
            return(PAM_SUCCESS);
        }
    }

    /* zero it out */
    memset(&rbld_sock, 0, sizeof(struct sockaddr_un));

    if (debug) {
        syslog(LOG_INFO, "Trying to connect to RBLD...");
    }

    /* Set family to unix domain socket, copy our socket path to the socket path */
    rbld_sock.sun_family = AF_UNIX;
    strcpy(rbld_sock.sun_path, argv[1]);

    /* Try and connect to rbld */
    if (connect(socket_fd, (struct sockaddr *) &rbld_sock, sizeof(struct sockaddr_un)) != 0) {
        syslog(LOG_INFO, "Could not connect to socket");
        if (debug) {
            syslog(LOG_INFO, "Host: %s", pHost);
            syslog(LOG_INFO, "Service: %s", pService);
        }
        if (!strcmp(pService, "dovecot")) {
            return(PAM_USER_UNKNOWN);
        } else {
            return(PAM_SUCCESS);
        }
    }

    if (debug) {
        syslog(LOG_INFO, "Successfully connected to rbld");
    }

    if (debug) {
        syslog(LOG_INFO, "Host: %s", pHost);
        syslog(LOG_INFO, "Service: %s", pService);
    }

    /* Form our query */
    /* buffersize is listname + IP address + 3 (for space, newline, and \0) */
    char *buffer    = NULL;
    int  buffersize = strlen(argv[0]) + strlen(pHost) + 3;
    buffer = (char *) malloc(buffersize);
    n = snprintf(buffer, buffersize, "%s %s\n", argv[0], pHost);
    if (buffer == NULL) {
        if (debug) {
            syslog(LOG_INFO, "Could not allocate memory for query");
        }
        if (!strcmp(pService, "dovecot")) {
            return(PAM_USER_UNKNOWN);
        } else {
            return(PAM_SUCCESS);
        }
    }

    if (debug) {
        syslog(LOG_INFO, "Query string: %s", buffer);
    }

    /* Send our query */
    if (write(socket_fd, buffer, n) < 0) {
        syslog(LOG_INFO, "Error writing to rbld socket");
        close(socket_fd);
        free(buffer);
        if (!strcmp(pService, "dovecot")) {
            return(PAM_USER_UNKNOWN);
        } else {
            return(PAM_SUCCESS);
        }
    }

    /* Get our return */
    n = read(socket_fd, buffer, 1);

    /* If n is less than zero then there is an error */
    if (n < 0) {
        syslog(LOG_INFO, "Error reading from rbld");
        close(socket_fd);
        free(buffer);
        if (!strcmp(pService, "dovecot")) {
            return(PAM_USER_UNKNOWN);
        } else {
            return(PAM_SUCCESS);
        }
    }

    if (debug) {
        syslog(LOG_INFO, "Return from rbld: %d", n);
    }
    close(socket_fd);

    /* Return success if it's not in the list, error if it is */
    if (n > 0) {
        syslog(LOG_INFO, "%s is listed in %s", pHost, argv[0]);
        if (debug) {
            syslog(LOG_INFO, "Returning PAM_AUTH_ERR");
        }
        closelog();
        free(buffer);
        return(PAM_AUTH_ERR);
    } else {
        /* This is confusing.  Please see my explanation of Dovecot at the top */
        if (!strcmp(pService, "dovecot")) {
            if (debug) {
                syslog(LOG_INFO, "Service is Dovecot");
                syslog(LOG_INFO, "Returning PAM_USER_UNKNOWN");
            }
            closelog();
            free(buffer);
            return(PAM_USER_UNKNOWN);
        } else {
            if (debug) {
                syslog(LOG_INFO, "Returning PAM_AUTH_SUCCESS");
            }
            closelog();
            free(buffer);
            return(PAM_SUCCESS);
        }
    }
}
