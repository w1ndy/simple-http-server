#include "asnet.h"

int unblock_fd(int fd)
{
    int err, flag;

    flag = fcntl(fd, F_GETFL, 0);
    if(flag == -1) {
        ERROR("failed to retrieve file descriptor's flag: %s",
            strerror(errno));
        return err;
    }
    flag |= O_NONBLOCK;
    err = fcntl(fd, F_SETFL, flag);
    if(err) {
        ERROR("failed to set file descriptor's flag: %s",
            strerror(errno));
        return err;
    }
    return 0;
}

int add_epoll_sock(int epoll_fd, int sock_fd)
{
    struct epoll_event evt;
    int err;

    err = unblock_fd(sock_fd);
    if(err) {
        ERROR("unable to unblock file descriptor: %s", strerror(err));
        return err;
    }
    evt.data.fd = sock_fd;
    evt.events = EPOLLIN | EPOLLET;
    err = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock_fd, &evt);
    if(err) {
        ERROR("epoll_ctl failed: %s", strerror(err));
        return err;
    }
    return 0;
}

int net_create(async_net_t **asnet, const char *port)
{
    INFO("creating async net interface...");

    struct addrinfo ai, *ret, *iter;
    int err, flag;

    memset(&ai, 0, sizeof(struct addrinfo));
    ai.ai_family = AF_UNSPEC;
    ai.ai_socktype = SOCK_STREAM;
    ai.ai_flags = AI_PASSIVE;

    err = getaddrinfo(NULL, port, &ai, &ret);
    if(err) {
        ERROR("getaddrinfo failed: %s", gai_strerror(err));
        return err;
    }

    int sock_fd = -1, epoll_fd = -1;
    for(iter = ret; iter != NULL; iter = iter->ai_next) {
        DEBUG("enumerating address...");
        sock_fd = socket(
            iter->ai_family, iter->ai_socktype, iter->ai_protocol);
        if(sock_fd == -1) {
            WARNING("failed to create socket: %s", strerror(errno));
            continue;
        }
        err = bind(sock_fd, iter->ai_addr, iter->ai_addrlen);
        if(!err)
            break;
        WARNING("failed to bind: %s", strerror(errno));
        close(sock_fd);
        sock_fd = -1;
    }
    freeaddrinfo(ret);

    if(sock_fd == -1) {
        ERROR("no proper socket available: ", strerror(errno));
        return err;
    }

    err = unblock_fd(sock_fd);
    if(err) {
        ERROR("cannot unblock socket");
        return err;
    }

    err = listen(sock_fd, SOMAXCONN);
    if(err) {
        ERROR("unable to listen on server socket: %s", strerror(errno));
        return err;
    }

    epoll_fd = epoll_create1(0);
    if(epoll_fd == -1) {
        ERROR("failed to create epoll queue: %s", strerror(errno));
        return errno;
    }

    err = add_epoll_sock(epoll_fd, sock_fd);
    if(err) {
        ERROR("failed to add socket to epoll queue: %s", strerror(errno));
        return err;
    }

    *asnet = (async_net_t *)malloc(sizeof(async_net_t));
    if(!(*asnet)) {
        ERROR("insufficient memory");
        return ENOMEM;
    }

    (*asnet)->sock_fd = sock_fd;
    (*asnet)->epoll_fd = epoll_fd;
    (*asnet)->unrec_err = 0;
    (*asnet)->evt_group = (struct epoll_event *)
        malloc(MAX_EVENTS * sizeof(struct epoll_event));

    if(!(*asnet)->evt_group) {
        ERROR("insufficient memory");
        free(*asnet);
        return ENOMEM;
    }

    (*asnet)->server_sock_err_handler = default_server_sock_err_handler;
    (*asnet)->child_sock_err_handler = default_child_sock_err_handler;
    (*asnet)->sock_hup_handler = default_sock_hup_handler;
    (*asnet)->new_connection_handler = default_new_connection_handler;
    (*asnet)->data_received_handler = default_data_received_handler;

    INFO("async net interface created successfully");
    return 0;
}

void net_accept_connections(async_net_t *asnet)
{
    new_connection_info_t cinfo;
    int fd, err;

    DEBUG("accepting new connections...");
    do {
        cinfo.addr_len = sizeof(cinfo.in_addr);
        fd = accept(asnet->sock_fd, &(cinfo.in_addr), &(cinfo.addr_len));
        if(fd == -1) {
            if(errno == EAGAIN || errno == EWOULDBLOCK)
                return ;
            else {
                ERROR("exception occured when accepting new connections:"
                    " %s", strerror(errno));
                return ;
            }
        }

        err = unblock_fd(fd);
        if(err) {
            ERROR("failed to unblock socket, dropping connection");
            close(fd);
            continue;
        }

        err = add_epoll_sock(asnet->epoll_fd, fd);
        if(err) {
            ERROR("failed to add socket to epoll queue: %s", strerror(err));
            return ;
        }

        asnet->new_connection_handler(asnet, fd, &cinfo);
    } while(1);
}

void net_read_connection(async_net_t *asnet, int fd)
{
    data_received_info_t rxinfo;

    do {
        rxinfo.length = read(fd, rxinfo.buf, BUFFER_SIZE);
        if(rxinfo.length < 0) {
            if(errno == EAGAIN || errno == EWOULDBLOCK)
                return ;
            else {
                ERROR("exception occured when retrieving data:"
                    " %s", strerror(errno));
                close(fd);
                return ;
            }
        } else {
            asnet->data_received_handler(asnet, fd, &rxinfo);
            if(rxinfo.length == 0)
                return ;
        }
    } while(1);
}

int net_process(async_net_t *asnet, int timeout)
{
    DEBUG("processing epoll events...");

    if(asnet->unrec_err) {
        WARNING("processing request was denied due to previous"
            " unrecoverable error.");
        return -1;
    }

    int n = epoll_wait(asnet->epoll_fd, asnet->evt_group, MAX_EVENTS, timeout);
    if(n < 0) {
        ERROR("epoll error: ", strerror(errno));
        return errno;
    }
    DEBUG("%d events received", n);

    int i;
    for(i = 0; i < n; i++) {
        if(asnet->evt_group[i].events & EPOLLERR) {
            if(asnet->evt_group[i].data.fd == asnet->sock_fd) {
                asnet->server_sock_err_handler(
                    asnet, asnet->evt_group[i].data.fd, 0);
                close(asnet->evt_group[i].data.fd);
            } else {
                asnet->child_sock_err_handler(
                    asnet, asnet->evt_group[i].data.fd, 0);
                close(asnet->evt_group[i].data.fd);
            }
        } else if(asnet->evt_group[i].events & EPOLLHUP) {
            asnet->sock_hup_handler(asnet, asnet->evt_group[i].data.fd, 0);
            close(asnet->evt_group[i].data.fd);
        } else if(asnet->evt_group[i].events & EPOLLIN) {
            if(asnet->evt_group[i].data.fd == asnet->sock_fd) {
                net_accept_connections(asnet);
            } else {
                net_read_connection(asnet, asnet->evt_group[i].data.fd);
            }
        }
    }

    return 0;
}

void net_free(async_net_t **asnet)
{
    if(*asnet) {
        close((*asnet)->sock_fd);
        close((*asnet)->epoll_fd);
        free((*asnet)->evt_group);
        free(*asnet);
        *asnet = NULL;
    }
}
