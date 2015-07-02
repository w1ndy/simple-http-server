#ifndef __BUFFERPOOL_H__
#define __BUFFERPOOL_H__

#define DEFAULT_ALLOCATED_BLOCKS    8
#define DOUBLE_THRESHOLD            1024

#include <pthread.h>
#include "rbtree.h"

typedef struct tag_buf_block
{
    void *data;
    struct tag_buf_block *alloc_next;
    struct tag_buf_block *free_next;
} buf_block_t;

typedef struct
{
    int block_cnt;
    int block_size;
    int byte_allocated;

    buf_block_t *free_chain;
    buf_block_t *alloc_chain;

    rbtree_t *alloc_index;
    pthread_mutex_t lock;
} bufferpool_t;

bufferpool_t *bufferpool_create(int size_per_block);
int           bufferpool_make(bufferpool_t *pool);
int           bufferpool_make_n(bufferpool_t *pool, int n);
void         *bufferpool_alloc(bufferpool_t *pool);
void         *bufferpool_alloc_threadsafe(bufferpool_t *pool);
void          bufferpool_dealloc(bufferpool_t *pool, void *buf);
void          bufferpool_dealloc_threadsafe(bufferpool_t *pool, void *buf);
void          bufferpool_free(bufferpool_t *pool, int assume_freed);
void          bufferpool_test();

#endif // __BUFFERPOOL_H__
