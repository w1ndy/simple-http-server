#include "dictionary.h"

#include <assert.h>

int dict_compfunc(const void *a, const void *b)
{
    dict_item_t *da = (dict_item_t *) a;
    dict_item_t *db = (dict_item_t *) b;
    if(da->keyhash < db->keyhash) return -1;
    else return (da->keyhash == db->keyhash) ? 0 : 1;
}

dict_t *dict_init()
{
    return rbtree_init(dict_compfunc);
}

void dict_put(dict_t *dict, const char *key, const char *value)
{
    dict_item_t *item = (dict_item_t *)malloc(sizeof(dict_item_t));

    item->weakref = 0;
    item->key = (char *)malloc(strlen(key) + 1);
    strcpy(item->key, key);
    item->keyhash = rbtree_hash_string(item->key);
    item->value = (char *)malloc(strlen(value) + 1);
    strcpy(item->value, value);
    item->next = NULL;

    dict_item_t *orig = rbtree_find(dict, item);
    if(orig) item->next = orig;
    rbtree_insert(dict, item);
}

void dict_put_weak(dict_t *dict, char *key, char *value)
{
    dict_item_t *item = (dict_item_t *)malloc(sizeof(dict_item_t));

    item->weakref = 1;
    item->key = key;
    item->keyhash = rbtree_hash_string(key);
    item->value = value;
    item->next = NULL;
    dict_item_t *orig = rbtree_find(dict, item);
    if(orig) item->next = orig;

    rbtree_insert(dict, item);
}

char *dict_get(dict_t *dict, const char *key)
{
    dict_item_t search_key = { .keyhash = rbtree_hash_string(key) };
    dict_item_t *item = rbtree_find(dict, &search_key);
    while(item && strcmp(item->key, key) != 0) item = item->next;
    if(!item) return NULL;
    return item->value;
}

void dict_remove(dict_t *dict, const char *key)
{
    dict_item_t search_key = { .keyhash = rbtree_hash_string(key) };
    dict_item_t *item = rbtree_find(dict, &search_key), *head, *s = NULL;
    head = item;
    while(item && !strcmp(item->key, key)) s = item, item = item->next;
    if(!item) return ;

    if(s != NULL || item->next != NULL) {
        if(s) s->next = item->next, s = head;
        else s = item->next;
        rbtree_insert(dict, s);
    } else {
        rbtree_remove(dict, &search_key);
    }

    if(!item->weakref) {
        free(item->key);
        free(item->value);
    }
    free(item);
}

void dict_free(dict_t *dict)
{
    rbtree_free(dict);
}

void dict_rand_string(char *buf, int len)
{
    int p;
    while(len--)
        *buf++ = ((p = rand() % 52) >= 26) ? (p - 26 + 'A') : (p + 'a');
    *buf = '\0';
}

void dict_test()
{
    puts("Dictionary Test (Strong Copy)");
    dict_t *d = dict_init();
    int i, j;
    char key[1000][11], value[1000][11];
    puts("Inserting items into dictionary...");
    for(i = 0; i < 1000; i++) {
        dict_rand_string(key[i], 10);
        dict_rand_string(value[i], 10);
        dict_put(d, key[i], value[i]);
    }
    puts("Reading random items out of dictionary...");
    for(i = 0; i < 500; i++) {
        j = rand() % 1000;
        const char *p = dict_get(d, key[j]);
        assert(strcmp(p, value[j]) == 0 && "value not match");
    }
    puts("Freeing dictionary...");
    dict_free(d);
    puts("Dictionary Test (Weak Copy)");
    d = dict_init();
    puts("Inserting items into dictionary...");
    for(i = 0; i < 1000; i++){
        dict_put_weak(d, key[i], value[i]);
    }
    puts("Reading random items out of dictionary...");
    for(i = 0; i < 500; i++) {
        j = rand() % 1000;
        const char *p = dict_get(d, key[j]);
        assert(strcmp(p, value[j]) == 0 && "value not match");
    }
    puts("Freeing dictionary...");
    dict_free(d);
    puts("Dictionary Test completed.");
}
