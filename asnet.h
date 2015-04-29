#ifndef __ASNET_H__
#define __ASNET_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <errno.h>
#include <netdb.h>
#include <ctype.h>
#include <fcntl.h>

#include "log.h"

#define MAX_EVENTS  32
#define MAX_HOST    1025
#define MAX_SERV    32
#define BUFFER_SIZE 512

struct tag_async_net;
typedef void (*evt_handler_t)(struct tag_async_net *asnet, int fd, void *info);

typedef struct tag_async_net {
    int sock_fd;
    int epoll_fd;
    struct epoll_event *evt_group;

    evt_handler_t server_sock_err_handler;
    evt_handler_t child_sock_err_handler;
    evt_handler_t sock_hup_handler;
    evt_handler_t new_connection_handler;
    evt_handler_t data_received_handler;

    int unrec_err;
} async_net_t;

typedef struct {
    struct sockaddr in_addr;
    int addr_len;
} new_connection_info_t;

typedef struct {
    char buf[BUFFER_SIZE];
    int length;
} data_received_info_t;

static void default_server_sock_err_handler(
    struct tag_async_net *asnet, int fd, void *info)
{
    ERROR("epoll error on server socket, entering unrec state");
    asnet->unrec_err = 1;
}

static void default_child_sock_err_handler(
    struct tag_async_net *asnet, int fd, void *info)
{
    ERROR("epoll error on child socket");
}

static void default_sock_hup_handler(
    struct tag_async_net *asnet, int fd, void *info)
{
    INFO("remote closed connection unexpectedly.");
}

static void default_new_connection_handler(
    struct tag_async_net *asnet, int fd, void *info)
{
    new_connection_info_t *cinfo = (new_connection_info_t *) info;
    char hbuf[MAX_HOST], sbuf[MAX_SERV];
    int err = getnameinfo (&(cinfo->in_addr), cinfo->addr_len,
        hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
        NI_NUMERICHOST | NI_NUMERICSERV);
    if(err) {
        DEBUG("new connection %d accepted.", fd);
    } else {
        DEBUG("new connection %d from %s:%s accepted.", fd, hbuf, sbuf);
    }
}

static char _hex(int i)
{
    i &= 0xf;
    return (i >= 0xa) ? (i - 0xa + 'a') : (i + '0');
}

static void default_data_received_handler(
    struct tag_async_net *asnet, int fd, void *info)
{
    data_received_info_t *rxinfo = (data_received_info_t *) info;
    if(rxinfo->length == 0) {
        DEBUG("EOF received from %d", fd);
        return ;
    }

    char output[3 * BUFFER_SIZE + 1];
    size_t p = 0;
    int i;
    DEBUG("got %d bytes from %d", rxinfo->length, fd);
    for(i = 0; i < rxinfo->length; i++) {
        if(rxinfo->buf[i] == '\\') {
            output[p] = output[p + 1] = '\\';
            p += 2;
        } else if(!isprint(rxinfo->buf[i])) {
            output[p++] = '\\';
            switch(rxinfo->buf[i]) {
                case '\t':
                    output[p++] = 't';
                    break;
                case '\r':
                    output[p++] = 'r';
                    break;
                case '\n':
                    output[p++] = 'n';
                    break;
                default:
                    output[p++] = _hex(rxinfo->buf[i] >> 4);
                    output[p++] = _hex(rxinfo->buf[i]);
            }
        } else {
            output[p++] = rxinfo->buf[i];
        }
    }
    output[p] = '\0';
    DEBUG("interpreted data: %s", output);
}

int  net_create(async_net_t **asnet, const char *port);
int  net_process(async_net_t *asnet, int timeout);
void net_free(async_net_t **asnet);

#endif // __ASNET_H__
