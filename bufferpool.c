#include "bufferpool.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

#include "log.h"

int block_compfunc(const void *a, const void *b)
{
    intptr_t pa = (intptr_t)(((const buf_block_t *)a)->data);
    intptr_t pb = (intptr_t)(((const buf_block_t *)b)->data);
    if(pa < pb) return -1;
    else return (pa == pb) ? 0 : 1;
}

bufferpool_t *bufferpool_create(int size_per_block)
{
    assert(size_per_block > 0);
    bufferpool_t *pool = (bufferpool_t *)malloc(sizeof(bufferpool_t));
    if(!pool) {
        ERROR("insufficient memory");
        return NULL;
    }
    pool->byte_allocated = 0;
    pool->free_chain = NULL;
    pool->alloc_chain = NULL;
    pool->block_cnt = DEFAULT_ALLOCATED_BLOCKS;
    pool->block_size = size_per_block;
    pool->alloc_index = rbtree_init(block_compfunc);
    pthread_mutex_init(&pool->lock, 0);
    bufferpool_make_n(pool, DEFAULT_ALLOCATED_BLOCKS);
    return pool;
}

int bufferpool_make(bufferpool_t *pool)
{
    buf_block_t *b = (buf_block_t *)malloc(sizeof(buf_block_t));
    if(!b) {
        ERROR("insufficient memory");
        return -1;
    }
    b->data = malloc(pool->block_size);
    if(!b->data) {
        ERROR("insufficient memory");
        free(b);
        return -1;
    }

    b->alloc_next = (pool->alloc_chain) ? pool->alloc_chain : NULL;
    pool->alloc_chain = b;
    b->free_next = (pool->free_chain) ? pool->free_chain : NULL;
    pool->free_chain = b;
    pool->byte_allocated += pool->block_size + sizeof(buf_block_t);

    return 0;
}

int bufferpool_make_n(bufferpool_t *pool, int n)
{
    int i, cnt = 0;;
    for(i = 0; i < n; i++)
        cnt += (bufferpool_make(pool) == 0) ? 1 : 0;
    printf("bufferpool: extending pool by %d\n", cnt);
    return cnt;
}

void *bufferpool_alloc(bufferpool_t *pool)
{
    unsigned int hash;
    buf_block_t *b, *prev;
    if(!pool->free_chain) {
        int cnt;
        if(pool->block_cnt < DOUBLE_THRESHOLD) {
            cnt = bufferpool_make_n(pool, pool->block_cnt);
        } else {
            cnt = bufferpool_make_n(pool, DOUBLE_THRESHOLD);
        }

        if(!cnt) {
            ERROR("insufficient memory");
            return NULL;
        }
        pool->block_cnt += cnt;
    }

    b = pool->free_chain;
    pool->free_chain = b->free_next;
    b->free_next = NULL;
    prev = rbtree_find(pool->alloc_index, b);
    if(prev != NULL)
        b->free_next = prev;
    rbtree_insert(pool->alloc_index, b);
    return b->data;
}

void *bufferpool_alloc_threadsafe(bufferpool_t *pool)
{
    void *buf;
    pthread_mutex_lock(&pool->lock);
    buf = bufferpool_alloc(pool);
    pthread_mutex_unlock(&pool->lock);
    return buf;
}

void bufferpool_dealloc(bufferpool_t *pool, void *buf)
{
    buf_block_t search_key = { .data = buf };
    buf_block_t *b = rbtree_find(pool->alloc_index, &search_key),
                *s = NULL, *head;
    head = b;
    while(b && b->data != buf) s = b, b = b->free_next;
    if(b == NULL) {
        WARNING("unassigned buffer deallocating, will be freed directly");
        free(buf);
        return ;
    } else {
        if(s != NULL || b->free_next) {
            if(s) s->free_next = b->free_next, s = head;
            else s = b->free_next;
            rbtree_insert(pool->alloc_index, s);
        } else
            rbtree_remove(pool->alloc_index, b);
        b->free_next = pool->free_chain;
        pool->free_chain = b;
    }
}

void bufferpool_dealloc_threadsafe(bufferpool_t *pool, void *buf)
{
    pthread_mutex_lock(&pool->lock);
    bufferpool_dealloc(pool, buf);
    pthread_mutex_unlock(&pool->lock);
}

void bufferpool_free(bufferpool_t *pool, int assume_freed)
{
    if(!assume_freed && !rbtree_is_empty(pool->alloc_index)) {
        WARNING("some buffer still in use");
    }

    buf_block_t *b;
    while(pool->alloc_chain) {
        b = pool->alloc_chain;
        pool->alloc_chain = b->alloc_next;
        free(b->data);
        free(b);
    }
    pthread_mutex_destroy(&pool->lock);
    free(pool);
}

void bufferpool_test()
{
    int i;
    bufferpool_t *pool = bufferpool_create(sizeof(int));
    int *arr[5000];
    DEBUG("bufferpool alloc test");
    for(i = 0; i < 5000; i++) {
        arr[i] = (int*)bufferpool_alloc(pool);
        (*arr[i]) = 0;
    }
    DEBUG("bufferpool dealloc test");
    for(i = 0; i < 5000; i++) {
        bufferpool_dealloc(pool, arr[i]);
    }
    bufferpool_free(pool, 0);
}
