#include "conn.h"

#include "alarm.h"
#include "bufferpool.h"

bufferpool_t *conn_pool, *conn_list_pool, *reqbuf_pool;
rbtree_t conn_index;
conn_list_t *active_conns;
async_net_t *net;

pthread_mutex_t connmgr_lock;

void timed_out_handler(void *data)
{
    int fd = (int)(intptr_t)data;
    connmgr_kill_connection(fd);
}

void child_sock_err_handler(struct tag_async_net *asnet, int fd, void *info)
{
    default_child_sock_err_handler(asnet, fd, info);
    connmgr_kill_connection(fd);
}

void sock_hup_handler(struct tag_async_net *asnet, int fd, void *info)
{
    default_sock_hup_handler(asnet, fd, info);
    connmgr_kill_connection(fd);
}

void new_connection_handler(struct tag_async_net *asnet, int fd, void *info)
{
    default_new_connection_handler(asnet, fd, info);
    conn_list_t *p = (conn_list_t *)bufferpool_alloc(conn_list_pool);
    p->conn = (conn_t *)bufferpool_alloc(conn_pool);
    p->conn->fd = fd;
    p->conn->reqbuf = (char *)bufferpool_alloc(reqbuf_pool);
    p->conn->length = 0;
    alarm_set(fd, REQUEST_TIME_OUT, timed_out_handler, (void*)(intptr_t)fd);
    pthread_mutex_lock(&connmgr_lock);
    p->prev = NULL;
    p->next = active_conns;
    if(active_conns) active_conns->prev = p;
    active_conns = p;
    conn_index = rbtree_insert(conn_index, p->conn->fd, p);
    pthread_mutex_unlock(&connmgr_lock);
}

void data_received_handler(struct tag_async_net *asnet, int fd, void *info)
{
    default_data_received_handler(asnet, fd, info);
    data_received_info_t *rxinfo = (data_received_info_t *) info;
    pthread_mutex_lock(&connmgr_lock);
    conn_list_t *p = rbtree_find(conn_index, fd);
    pthread_mutex_unlock(&connmgr_lock);
    if(p == NULL) {
        ERROR("unacknowledge connection %d", fd);
        return ;
    }
    if(rxinfo->length + p->conn->length < MAX_REQUEST_SIZE) {
        memcpy(p->conn->reqbuf + p->conn->length, rxinfo->buf, rxinfo->length);
        p->conn->length += rxinfo->length;
        if(p->conn->length > 4 &&
                !strcmp(&p->conn->reqbuf[p->conn->length - 4], "\r\n\r\n")) {
            INFO("http request has been received");
            // spawn a new thread and start processing
        }
    } else {
        WARNING("connection %d exceeds request buffer capacity", fd);
        connmgr_kill_connection(fd);
    }
}

void connmgr_init(async_net_t *asnet)
{
    conn_list_pool = bufferpool_create(sizeof(conn_list_t));
    conn_pool = bufferpool_create(sizeof(conn_t));
    reqbuf_pool = bufferpool_create(MAX_REQUEST_SIZE);
    conn_index = rbtree_init();
    pthread_mutex_init(&connmgr_lock, 0);
    net = asnet;
    active_conns = NULL;
    net->child_sock_err_handler = child_sock_err_handler;
    net->sock_hup_handler = sock_hup_handler;
    net->data_received_handler = data_received_handler;
    net->new_connection_handler = new_connection_handler;
}

void connmgr_kill_connection(int fd)
{
    pthread_mutex_lock(&connmgr_lock);
    conn_list_t *p = rbtree_find(conn_index, fd);
    if(!p) goto kill_fin;
    conn_index = rbtree_remove(conn_index, fd);
    close(p->conn->fd);
    //alarm_cancel(p->conn->timeout_alarm_id);
    bufferpool_dealloc(reqbuf_pool, p->conn->reqbuf);
    bufferpool_dealloc(conn_pool, p->conn);
    if(p->prev) p->prev->next = p->next;
    if(p->next) p->next->prev = p->prev;
    if(p == active_conns) active_conns = NULL;
    bufferpool_dealloc(conn_list_pool, p);

kill_fin:
    pthread_mutex_unlock(&connmgr_lock);
}

void connmgr_close()
{
    pthread_mutex_lock(&connmgr_lock);
    net->child_sock_err_handler = default_child_sock_err_handler;
    net->sock_hup_handler = default_sock_hup_handler;
    net->data_received_handler = default_data_received_handler;
    net->new_connection_handler = default_new_connection_handler;

    rbtree_free(conn_index);
    conn_list_t *p = active_conns, *s;
    while(active_conns) {
        p = active_conns;
        active_conns = active_conns->next;
        close(p->conn->fd);
        //alarm_cancel(p->conn->timeout_alarm_id);
        bufferpool_dealloc(reqbuf_pool, p->conn->reqbuf);
        bufferpool_dealloc(conn_pool, p->conn);
        bufferpool_dealloc(conn_list_pool, p);
    }
    bufferpool_free(reqbuf_pool);
    bufferpool_free(conn_pool);
    bufferpool_free(conn_list_pool);
    pthread_mutex_unlock(&connmgr_lock);
    pthread_mutex_destroy(&connmgr_lock);
}
