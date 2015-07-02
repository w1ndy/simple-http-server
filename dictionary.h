#ifndef __DICTIONARY_H__
#define __DICTIONARY_H__

#include <stdlib.h>
#include <string.h>

#include "rbtree.h"

typedef rbtree_t dict_t;

typedef struct tag_dict_item
{
    int weakref;
    char *key;
    int keyhash;
    char *value;
    struct tag_dict_item *next;
} dict_item_t;

dict_t *dict_init();
void    dict_put(dict_t *dict, const char *key, const char *value);
void    dict_put_weak(dict_t *dict, char *key, char *value);
char   *dict_get(dict_t *dict, const char *key);
void    dict_remove(dict_t *dict, const char *key);
void    dict_free(dict_t *dict);
void    dict_rand_string(char *buf, int len);
void    dict_test();

#endif // __DICTIONARY_H__
