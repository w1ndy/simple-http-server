#include "alarm.h"

#include <pthread.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "log.h"

alarm_queue_t *queue;
alarm_queue_t new_alarm;
int thread_close;

pthread_t alarm_thread;
pthread_cond_t new_alarm_cond, alarm_set_cond;
pthread_mutex_t alarm_mutex, main_mutex;

void *alarm_main(void *param)
{
    alarm_queue_t *s, *p;
    int err;

    INFO("alarm thread has been spawned");
    pthread_mutex_lock(&alarm_mutex);
    do {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        DEBUG("alarm thread is going to sleep");
        if(queue == NULL) {
            DEBUG("no task arranged for alarm");
            err = pthread_cond_wait(&new_alarm_cond, &alarm_mutex);
        } else {
            DEBUG("next task will be triggered in %d seconds",
                queue->sched_time.tv_sec - ts.tv_sec);
            err = pthread_cond_timedwait(&new_alarm_cond, &alarm_mutex,
                &queue->sched_time);
        }
        if(err == ETIMEDOUT) {
            DEBUG("alarm task triggered");
            queue->handler(queue->data);
            s = queue;
            queue = queue->next;
            free(s);
        } else if(!err) {
            if(!thread_close) {
                clock_gettime(CLOCK_REALTIME, &ts);
                DEBUG("new task is added to alarm, executing in %d seconds",
                    new_alarm.sched_time.tv_sec - ts.tv_sec);
                if(!queue ||
                        queue->sched_time.tv_sec >
                        new_alarm.sched_time.tv_sec) {
                    s = (alarm_queue_t *)malloc(sizeof(alarm_queue_t));
                    memcpy(s, &new_alarm, sizeof(alarm_queue_t));
                    s->next = queue;
                    queue = s;
                } else {
                    p = queue, s = queue->next;
                    while(s &&
                            s->sched_time.tv_sec < new_alarm.sched_time.tv_sec)
                        p = s, s = s->next;
                    s = (alarm_queue_t *)malloc(sizeof(alarm_queue_t));
                    memcpy(s, &new_alarm, sizeof(alarm_queue_t));
                    s->next = p->next;
                    p->next = s;
                }
            }
            DEBUG("alarm action completed, notifying main thread");
            pthread_mutex_lock(&main_mutex);
            pthread_cond_signal(&alarm_set_cond);
            pthread_mutex_unlock(&main_mutex);
        }
    } while(!thread_close);
    pthread_mutex_unlock(&alarm_mutex);
}

void alarm_init()
{
    int err;

    thread_close = 0;
    queue = NULL;
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

void alarm_set(int seconds, alarm_handler_t handler, void *data)
{
    DEBUG("trying to set an alarm in %d seconds", seconds);
    clock_gettime(CLOCK_REALTIME, &(new_alarm.sched_time));
    new_alarm.sched_time.tv_sec += seconds;
    new_alarm.handler = handler;
    new_alarm.data = data;

    DEBUG("locking alarm mutex");
    pthread_mutex_lock(&alarm_mutex);
    DEBUG("signalling new alarm");
    pthread_cond_signal(&new_alarm_cond);
    DEBUG("locking main mutex");
    pthread_mutex_lock(&main_mutex);
    DEBUG("unlocking alarm mutex");
    pthread_mutex_unlock(&alarm_mutex);
    DEBUG("waiting alarm set condition");
    pthread_cond_wait(&alarm_set_cond, &main_mutex);
    DEBUG("unlock main mutex");
    pthread_mutex_unlock(&main_mutex);
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

    alarm_queue_t *p = queue, *s;
    while(p) {
        s = p;
        p = p->next;
        free(s);
    }
}
