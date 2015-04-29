#ifndef __ALARM_H__
#define __ALARM_H__

#include <time.h>

typedef void (*alarm_handler_t)(void *data);

typedef struct tag_alarm_queue
{
    int id;
    struct timespec sched_time;
    alarm_handler_t handler;
    void *data;
    struct tag_alarm_queue *next;
} alarm_queue_t;

void alarm_init();
void alarm_set(int id, int seconds, alarm_handler_t handler, void *data);
void alarm_cancel(int alarm_id);
void alarm_close();
void alarm_close_wait();

#endif // __ALARM_H__
