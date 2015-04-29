#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "log.h"
#include "asnet.h"
#include "alarm.h"
#include "rbtree.h"

void duckduckduck(void *eat)
{
    printf("duck is eating!");
}

int main(int argc, char *argv[])
{
    srand(time(0));
    log_init("httpsrv.log", 1);
    log_set_level(LOG_LEVEL_DEBUG);
    DEBUG("httpsrv has started.");

    //rbtree_random_test(10, 10240, 5000, 5000, 200);
    //rbtree_key_value_test(RBTREE_TEST_MAX_KEY, 50);
    rbtree_stress_test(1000000);
    //test_rbtree_case();
    /*alarm_init();
    alarm_set(5, duckduckduck, 0);
    alarm_set(2, duckduckduck, 0);
    alarm_set(4, duckduckduck, 0);
    alarm_set(6, duckduckduck, 0);
    alarm_set(1, duckduckduck, 0);
    alarm_set(5, duckduckduck, 0);
    async_net_t *net;
    if(net_create(&net, "80"))
        return -1;
    while(1)
        net_process(net, -1);
    net_free(&net);
    alarm_close();
    log_close();*/
    return 0;
}
