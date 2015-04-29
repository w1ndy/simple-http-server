#include <stdio.h>
#include <stdlib.h>

#include "log.h"
#include "asnet.h"
#include "alarm.h"

void duckduckduck(void *eat)
{
    printf("duck is eating!");
}

int main(int argc, char *argv[])
{
    log_init("httpsrv.log", 1);
    log_set_level(LOG_LEVEL_DEBUG);
    DEBUG("httpsrv has started.");

    alarm_init();
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
    log_close();
    return 0;
}
