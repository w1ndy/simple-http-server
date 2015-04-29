#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>

#include "log.h"
#include "asnet.h"
#include "alarm.h"
#include "rbtree.h"
#include "conn.h"

async_net_t *net;

void sig_handler(int n)
{
    alarm_close();
    connmgr_close();
    net_free(&net);
    log_close();
    exit(0);
}

int main(int argc, char *argv[])
{
    srand(time(0));
    log_init("httpsrv.log", 1);
    log_set_level(LOG_LEVEL_DEBUG);
    DEBUG("httpsrv has started.");

    bufferpool_test();
    //rbtree_random_test(10, 10240, 5000, 5000, 200);
    //rbtree_key_value_test(RBTREE_TEST_MAX_KEY, 50);
    //rbtree_stress_test(1000000);
    //test_rbtree_case();
    signal(SIGINT, sig_handler);
    alarm_init();
    if(net_create(&net, "8080"))
        return -1;
    connmgr_init(net);
    while(1)
        net_process(net, -1);
    connmgr_close();
    net_free(&net);
    alarm_close();
    log_close();
    return 0;
}
