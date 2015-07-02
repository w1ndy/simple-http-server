#include "alarm.h"

#include <pthread.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "bufferpool.h"
#include "rbtree.h"

alarm_t new_alarm;

int thread_close, cancel_alarm;

pthread_t alarm_thread;
pthread_cond_t new_alarm_cond, alarm_set_cond;
pthread_mutex_t alarm_mutex, main_mutex;

int alarm_compfunc(const void *a, const void *b)
{
    const alarm_t *aa = (const alarm_t *) a;
    const alarm_t *ab = (const alarm_t *) b;
    if(aa->id < ab->id) return -1;
    else return (aa->id == ab->id) ? 0 : 1;
}

bufferpool_t *pool, *queue_pool;
alarm_queue_t *queue;
rbtree_t *alarms;

int _compare_time_if_less(struct timespec *a, struct timespec *b)
{
    return a->tv_sec < b->tv_sec;
}

void _insert_alarm_task_to_queue(alarm_t *a)
{
    alarm_queue_t *q = bufferpool_alloc(queue_pool);
    q->alarm = a;
    q->alarm->in_queue = q;

    if(!queue) {
        q->prev = q->next = NULL;
        queue = q;
    } else {
        alarm_queue_t *iter = queue;
        while(iter->next &&
            _compare_time_if_less(
                &(iter->next->alarm->sched_time),
                &(a->sched_time)))
                    iter = iter->next;
        q->next = iter->next;
        q->prev = iter;
        if(q->next) q->next->prev = q;
        iter->next = q;
    }
}

void _remove_alarm_task_from_queue(alarm_t *a)
{
    if(queue == a->in_queue) {
        queue = a->in_queue->next;
        if(queue) queue->prev = NULL;
    } else {
        if(a->in_queue->prev)
            a->in_queue->prev->next = a->in_queue->next;
        if(a->in_queue->next)
            a->in_queue->next->prev = a->in_queue->prev;
    }
    bufferpool_dealloc(queue_pool, a->in_queue);
    bufferpool_dealloc(pool, a);
}

void _add_alarm_task()
{
    alarm_t *a = bufferpool_alloc(pool);
    memcpy(a, &new_alarm, sizeof(alarm_t));

    alarm_t *old_a = rbtree_insert(alarms, a);
    if(old_a)
        _remove_alarm_task_from_queue(old_a);
    _insert_alarm_task_to_queue(a);
}

void _execute_alarm_task(alarm_t *a)
{
    a->handler(a->data);
    rbtree_remove(alarms, a);
    _remove_alarm_task_from_queue(a);
}

void _cancel_alarm_task()
{
    alarm_t search_key = { .id = cancel_alarm };
    alarm_t *ret = rbtree_find(alarms, &search_key);
    if(ret) {
        rbtree_remove(alarms, ret);
        _remove_alarm_task_from_queue(ret);
    }
}

void *alarm_main(void *param)
{
    pthread_mutex_lock(&alarm_mutex);

    int err;
    pool = bufferpool_create(sizeof(alarm_t));
    queue_pool = bufferpool_create(sizeof(alarm_queue_t));
    queue = NULL;
    alarms = rbtree_init(alarm_compfunc);

    INFO("alarm thread has been spawned");
    do {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        alarm_t *next_task;
        if(rbtree_is_empty(alarms)) {
            DEBUG("alarm: no task arranged, sleeping");
            err = pthread_cond_wait(&new_alarm_cond, &alarm_mutex);
        } else {
            next_task = queue->alarm;
            if(_compare_time_if_less(&ts, &(next_task->sched_time))) {
                DEBUG("alarm: next task will be triggered in %d seconds",
                    next_task->sched_time.tv_sec - ts.tv_sec);
                err = pthread_cond_timedwait(&new_alarm_cond, &alarm_mutex,
                    &next_task->sched_time);
            } else {
                DEBUG("alarm: next task will be triggered now.");
                err = ETIMEDOUT;
            }
        }
        if(err == ETIMEDOUT) {
            DEBUG("alarm: task triggered");
            _execute_alarm_task(next_task);
        } else if(!err) {
            if(!thread_close) {
                if(cancel_alarm >= 0) {
                    DEBUG("alarm: cancelling alarm %d", cancel_alarm);
                    _cancel_alarm_task();
                } else {
                    clock_gettime(CLOCK_REALTIME, &ts);
                    DEBUG("alarm: new task is added to alarm "
                        " executing in %d seconds",
                        new_alarm.sched_time.tv_sec - ts.tv_sec);
                    _add_alarm_task();
                }
            } else {
                rbtree_free(alarms);
                bufferpool_free(pool, 0);
                bufferpool_free(queue_pool, 0);
                pthread_mutex_unlock(&alarm_mutex);
            }
            DEBUG("alarm action completed, notifying main thread");
            pthread_mutex_lock(&main_mutex);
            pthread_cond_signal(&alarm_set_cond);
            pthread_mutex_unlock(&main_mutex);
        }
    } while(!thread_close);
}

void alarm_init()
{
    int err;

    thread_close = 0;
    cancel_alarm = -1;
    pthread_cond_init(&new_alarm_cond, 0);
    pthread_cond_init(&alarm_set_cond, 0);
    pthread_mutex_init(&alarm_mutex, 0);
    pthread_mutex_init(&main_mutex, 0);
    err = pthread_create(&alarm_thread, NULL, alarm_main, NULL);
    if(err) {
        ERROR("alarm thread could not be created: %s", strerror(errno));
    } else {
        INFO("alarm component initialized.");
    }
}

void alarm_set(int id, int seconds, alarm_handler_t handler, void *data)
{
    DEBUG("trying to set an alarm in %d seconds", seconds);
    clock_gettime(CLOCK_REALTIME, &(new_alarm.sched_time));
    new_alarm.id = id;
    new_alarm.sched_time.tv_sec += seconds;
    new_alarm.handler = handler;
    new_alarm.data = data;

    pthread_mutex_lock(&alarm_mutex);
    pthread_cond_signal(&new_alarm_cond);
    pthread_mutex_lock(&main_mutex);
    pthread_mutex_unlock(&alarm_mutex);
    pthread_cond_wait(&alarm_set_cond, &main_mutex);
    pthread_mutex_unlock(&main_mutex);
}

void alarm_cancel(int alarm_id)
{
    cancel_alarm = alarm_id;

    pthread_mutex_lock(&alarm_mutex);
    pthread_cond_signal(&new_alarm_cond);
    pthread_mutex_lock(&main_mutex);
    pthread_mutex_unlock(&alarm_mutex);
    pthread_cond_wait(&alarm_set_cond, &main_mutex);
    pthread_mutex_unlock(&main_mutex);

    cancel_alarm = -1;
}

void alarm_close()
{
    pthread_mutex_lock(&alarm_mutex);
    thread_close = 1;
    pthread_cond_signal(&new_alarm_cond);
    pthread_mutex_lock(&main_mutex);
    pthread_mutex_unlock(&alarm_mutex);
    pthread_cond_wait(&alarm_set_cond, &main_mutex);
    pthread_mutex_unlock(&main_mutex);

    pthread_cond_destroy(&new_alarm_cond);
    pthread_cond_destroy(&alarm_set_cond);
    pthread_mutex_destroy(&alarm_mutex);
    pthread_mutex_destroy(&main_mutex);
}

void handler(void *data)
{
    printf("handler %d has been activated\n", (int)(intptr_t)data);
}

void alarm_test()
{
    alarm_init();
    alarm_set(0, 1, handler, (void *)(intptr_t)0);
    alarm_set(1, 1, handler, (void *)(intptr_t)1);
    alarm_set(2, 2, handler, (void *)(intptr_t)2);
    alarm_set(3, 2, handler, (void *)(intptr_t)3);
    alarm_set(4, 4, handler, (void *)(intptr_t)4);
    alarm_set(5, 3, handler, (void *)(intptr_t)5);
    alarm_set(6, 4, handler, (void *)(intptr_t)6);
    alarm_set(7, 5, handler, (void *)(intptr_t)7);
    sleep(3);
    alarm_cancel(7);
    sleep(10);
    alarm_close();
}
