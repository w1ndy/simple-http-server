#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dictionary.h"
#include "rbtree.h"
#include "bufferpool.h"
#include "alarm.h"

#include "log.h"

int main()
{
    log_init("test.log", 1);
    log_set_level(LOG_LEVEL_DEBUG);
    puts("rbtree_random_test");
    rbtree_random_test(10, 1000, 500, 500, 300);
    puts("rbtree_stress_test");
    rbtree_stress_test(100000);
    puts("dictionary_test");
    dict_test();
    puts("bufferpool_test");
    bufferpool_test();
    puts("alarm_test");
    alarm_test();
    log_close();
    return 0;
}
