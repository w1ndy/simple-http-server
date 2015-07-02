#ifndef __ALARM_H__
#define __ALARM_H__

#include <time.h>

typedef void (*alarm_handler_t)(void *data);

struct tag_alarm_queue;

typedef struct
{
    int id;
    struct timespec sched_time;
    alarm_handler_t handler;
    void *data;
    struct tag_alarm_queue *in_queue;
} alarm_t;

typedef struct tag_alarm_queue
{
    struct tag_alarm_queue *prev;
    alarm_t *alarm;
    struct tag_alarm_queue *next;
}alarm_queue_t;

void alarm_init();
void alarm_set(int id, int seconds, alarm_handler_t handler, void *data);
void alarm_cancel(int alarm_id);
void alarm_close();
void alarm_close_wait();
void alarm_test();

#endif // __ALARM_H__
