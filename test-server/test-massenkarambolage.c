/*
 * libwebsockets-test-massenkarambolage - echo test for Autobahn testsuite
 *
 * Implements only the server to test against Autobahn fuzzingclient.
 * Based on test-echo.c
 *
 * Copyright (C) 2010-2013 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <sys/time.h>
#include <assert.h>
#include <syslog.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#ifdef CMAKE_BUILD
#include "lws_config.h"
#endif

#include "../lib/libwebsockets.h"

#ifdef LWS_NO_SERVER
#error "This test requires server mode"
#endif


static int force_exit = 0;


#define MAX_ECHO_PAYLOAD 80000

struct per_session_data__echo {
    unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + MAX_ECHO_PAYLOAD + LWS_SEND_BUFFER_POST_PADDING];
    unsigned int len;
};

/* Get socket information */
static int get_fd_info(int fd)
{
    int sock_domain;
    socklen_t sock_len = sizeof(sock_domain);

    if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &sock_domain, &sock_len) != 0) {
        lwsl_err("... getsockopt failed.");
        return 1;
    }

    if (sock_domain == AF_INET) {
        /* socket is IPv4 */
        struct sockaddr_in sa;
        sock_len = sizeof(sa);
        if (getpeername(fd, (struct sockaddr *) &sa, &sock_len) == 0) {
            char str[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &(sa.sin_addr), str, INET_ADDRSTRLEN)) {
                lwsl_notice("... client have IPv4 address %s, port %d", str, ntohs(sa.sin_port));
                return 0;
            } else {
                lwsl_err("... sock_domain == AF_INET, inet_ntop failed.");
            }
        } else  {
            lwsl_err("... sock_domain == AF_INET, getpeername failed.");
        }
    } else if (sock_domain == AF_INET6) {
        /* socket is IPv6 */
        struct sockaddr_in6 sa;
        sock_len = sizeof(sa);
        if (getpeername(fd, (struct sockaddr *) &sa, &sock_len) == 0) {
            char str[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &(sa.sin6_addr), str, INET6_ADDRSTRLEN)) {
                lwsl_notice("... client have IPv6 address %s, port %d", str, ntohs(sa.sin6_port));
                return 0;
            } else {
                lwsl_err("... sock_domain == AF_INET6, inet_ntop failed.");
            }
        } else {
            lwsl_err("... sock_domain == AF_INET6, getpeername failed.");
        }

    } else {
        lwsl_err("... sock_domain %d is neither AF_INET nor AF_INET6.", sock_domain);
    }
    return 1;
}

static int callback_echo(struct libwebsocket_context *context,
    struct libwebsocket *wsi,
    enum libwebsocket_callback_reasons reason, void *user,
    void *in, size_t len)
{
    struct per_session_data__echo *pss = (struct per_session_data__echo *)user;
    int n;

    switch (reason) {
        
        case LWS_CALLBACK_ESTABLISHED: {
            lwsl_notice("LWS_CALLBACK_ESTABLISHED, pss == %p", pss);

            int fd = libwebsocket_get_socket_fd(wsi);
            lwsl_notice("... client fd: %d", fd);
            get_fd_info(fd);

            char url[128];
            lws_hdr_copy(wsi, url, sizeof(url), WSI_TOKEN_GET_URI);
            url[sizeof(url)-1] = '\0';
            lwsl_notice("... requested url: %s", url);

            pss->len = 0;
            return 0;
        }

        case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
            lwsl_notice("LWS_CALLBACK_FILTER_NETWORK_CONNECTION, "
                "pss == %p, in == %p", pss, in);
            return 0;

        case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
            lwsl_notice("LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION, "
                "pss == %p, in == %p, len == %zd", pss, in, len);
            lwsl_notice("... proto name == %s ", (const char *) in);

            char origin[256];
            if (lws_hdr_copy(wsi, origin, sizeof(origin), WSI_TOKEN_ORIGIN) > 0) {
                origin[sizeof(origin)-1] = '\0';
                lwsl_notice("... origin: %s", origin);
            } else {
                lwsl_notice("... no origin header given.");
            }
            return 0;

        case LWS_CALLBACK_CONFIRM_EXTENSION_OKAY:
            lwsl_notice("LWS_CALLBACK_CONFIRM_EXTENSION_OKAY, "
                "pss == %p, in == %p, len == %zd", pss, in, len);
            lwsl_notice("... extension == %s ", (const char *) in);
            return 0;

        case LWS_CALLBACK_SERVER_WRITEABLE:
            n = libwebsocket_write(wsi, &pss->buf[LWS_SEND_BUFFER_PRE_PADDING], pss->len, LWS_WRITE_BINARY);
            if (n < 0) {
                lwsl_err("ERROR %d writing to socket, hanging up\n", n);
                return 1;
            }
            if (n < (int)pss->len) {
                /* Handle this if this log appear when running the test */
                lwsl_err("Partial write, %d bytes remaining\n", ((int)pss->len) - n);
                return -1;
            }
            break;

        case LWS_CALLBACK_RECEIVE:
            if (len > MAX_ECHO_PAYLOAD) {
                lwsl_err("Server received %d bytes, bigger than %u, hanging up\n", (int) len, MAX_ECHO_PAYLOAD);
                return 1;
            }
            memcpy(&pss->buf[LWS_SEND_BUFFER_PRE_PADDING], in, len);
            pss->len = (unsigned int) len;
            libwebsocket_callback_on_writable(context, wsi);
            break;

        case LWS_CALLBACK_CLOSED:
            lwsl_notice("LWS_CALLBACK_CLOSED, pss == %p", pss);
            break;

        default:
            break;
    }

    return 0;
}



static struct libwebsocket_protocols protocols[] = {
    /* first protocol must always be HTTP handler */
    {
        "binary",       /* name */
        callback_echo,  /* callback */
        sizeof(struct per_session_data__echo)   /* per_session_data_size */
    },

    { NULL, NULL, 0 }   /* End of list */
};

void sighandler(int sig)
{
    force_exit = 1;
}

static struct option options[] = {
    { "help",   no_argument,        NULL, 'h' },
    { "debug",  required_argument,  NULL, 'd' },
    { "port",   required_argument,  NULL, 'p' },
    { NULL, 0, 0, 0 }
};

int main(int argc, char **argv)
{
    int n = 0;
    int listen_port = 7681;
    struct libwebsocket_context *context;
    int opts = 0;
    char interface_name[128] = "";
    const char *interface = NULL;
    int syslog_options = LOG_PID | LOG_PERROR;
    struct lws_context_creation_info info;
    int debug_level = 7;

    memset(&info, 0, sizeof info);

    while (n >= 0) {
        n = getopt_long(argc, argv, "i:h:d", options, NULL);
        if (n < 0)
            continue;
        switch (n) {
            case 'd':
                debug_level = atoi(optarg);
                break;
            case 'p':
                listen_port = atoi(optarg);
                break;
            case 'i':
                strncpy(interface_name, optarg, sizeof interface_name);
                interface_name[(sizeof interface_name) - 1] = '\0';
                interface = interface_name;
                break;
            case '?':
            case 'h':
                fprintf(stderr, "Usage: libwebsockets-test-massenkarambolage "
                        "[--port=<p>] "
                        "[-d <log bitfield>]\n");
                return 1;
                break;
            default:
                lwsl_err("Option %c not handled.\n", n);
                break;
        }
    }

    /* we will only try to log things according to our debug_level */
    setlogmask(LOG_UPTO (LOG_DEBUG));
    openlog("massenkarambolage", syslog_options, LOG_DAEMON);

    /* tell the library what debug level to emit and to send it to syslog */
    lws_set_log_level(debug_level, lwsl_emit_syslog);

    lwsl_notice("Running in server mode\n");

    info.port = listen_port;
    info.iface = interface;
    info.protocols = protocols;

#ifndef LWS_NO_EXTENSIONS
    info.extensions = libwebsocket_get_internal_extensions();
#endif

    info.gid = -1;
    info.uid = -1;
    info.options = opts;

    context = libwebsocket_create_context(&info);

    if (context == NULL) {
        lwsl_err("libwebsocket init failed\n");
        return -1;
    }

    signal(SIGINT, sighandler);

    n = 0;
    while (n >= 0 && !force_exit) {
        n = libwebsocket_service(context, 10);
    }
    lwsl_notice("exiting with n == %d\n", n);

    libwebsocket_context_destroy(context);

    lwsl_notice("exited cleanly\n");

    closelog();

    return 0;
}
