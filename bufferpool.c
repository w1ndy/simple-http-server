#include "bufferpool.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "log.h"

bufferpool_t *bufferpool_create(int size_per_block)
{
    assert(size_per_block > 0);
    bufferpool_t *pool = (bufferpool_t *)malloc(sizeof(bufferpool_t));
    if(!pool) {
        ERROR("insufficient memory");
        return NULL;
    }
    pool->free_chain = NULL;
    pool->alloc_chain = NULL;
    pool->block_cnt = DEFAULT_ALLOCATED_BLOCKS;
    pool->block_size = size_per_block;
    pool->alloc_index = rbtree_init();

    int i;
    for(i = 0; i < DEFAULT_ALLOCATED_BLOCKS; i++) {
    }
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

    b->alloc_next = (pool->alloc_chain) ? pool->alloc_chain->alloc_next : NULL;
    pool->alloc_chain = b;
    b->free_next = (pool->free_chain) ? pool->free_chain->free_next : NULL;
    pool->free_chain = b;

    return 0;
}

int bufferpool_make_n(bufferpool_t *pool, int n)
{
    int i, cnt = 0;;
    for(i = 0; i < n; i++)
        cnt += (bufferpool_make(pool) == 0) ? 1 : 0;
    return cnt;
}

void *bufferpool_alloc(bufferpool_t *pool)
{
    unsigned int hash;
    buf_block_t *b, *prev;
    if(pool->free_chain) {
        b = pool->free_chain;
        pool->free_chain = b->free_next;
        b->free_next = NULL;
        hash = rbtree_hash_mem((unsigned char *)(&b->data), sizeof(void *));
        prev = rbtree_find(pool->alloc_index, hash);
        if(prev != NULL)
            b->free_next = prev;
        pool->alloc_index = rbtree_insert(pool->alloc_index, hash, b);
        return b->data;
    }

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
    return bufferpool_alloc(pool);
}

void bufferpool_dealloc(bufferpool_t *pool, void *buf)
{
    unsigned int hash = rbtree_hash_mem(
        (unsigned char *)(&buf), sizeof(void *));
    buf_block_t *b = rbtree_find(pool->alloc_index, hash);
    while(b && b->data != buf) b = b->free_next;
    if(b == NULL) {
        WARNING("unassigned buffer deallocating, will be freed directly");
        free(buf);
        return ;
    } else {
        if(b->free_next)
            pool->alloc_index = rbtree_insert(
                pool->alloc_index, hash, b->free_next);
        else
            pool->alloc_index = rbtree_remove(pool->alloc_index, hash);
        b->free_next = pool->free_chain;
        pool->free_chain = b;
    }
}

void bufferpool_free(bufferpool_t *pool)
{
    if(pool->alloc_index != NULL) {
        WARNING("some buffer still in use");
    }

    buf_block_t *b;
    while(pool->alloc_chain) {
        b = pool->alloc_chain;
        pool->alloc_chain = b->alloc_next;
        free(b->data);
        free(b);
    }
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
    bufferpool_free(pool);
}
