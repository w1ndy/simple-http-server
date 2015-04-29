#ifndef __CONN_H__
#define __CONN_H__

#define MAX_REQUEST_SIZE    2048
#define REQUEST_TIME_OUT    15

#include <pthread.h>
#include "asnet.h"

typedef struct
{
    int fd;
    char *reqbuf;
    int length;
} conn_t;

typedef struct tag_conn_list
{
    struct tag_conn_list *prev;
    conn_t *conn;
    struct tag_conn_list *next;
} conn_list_t;

void connmgr_init(async_net_t *asnet);
void connmgr_kill_connection(int fd);
void connmgr_close();

#endif // __CONN_H__

