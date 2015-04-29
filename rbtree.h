#ifndef __RBTREE_H__
#define __RBTREE_H__

#define RBTREE_NEGRED   -1
#define RBTREE_RED      0
#define RBTREE_BLACK    1
#define RBTREE_DBLBLACK 2

#define RBTREE_TEST_MAX_KEY 5000

typedef struct tag_rbtree_node
{
    int key;
    void *data;
    int color;
    struct tag_rbtree_node *parent;
    struct tag_rbtree_node *left;
    struct tag_rbtree_node *right;
} rbtree_node_t;

typedef struct tag_rbtree_node *rbtree_t;

rbtree_t       rbtree_init();
rbtree_t       rbtree_insert(rbtree_t root, int key, void *data);
rbtree_t       rbtree_remove(rbtree_t root, int key);
rbtree_t       rbtree_new_node(int key, void *data, int color);
int            rbtree_validate(rbtree_t root);
void          *rbtree_find(rbtree_t root, int key);
void           rbtree_free(rbtree_t root);
void           rbtree_print(rbtree_t root);
unsigned int   rbtree_hash_string(const char *s);

void           rbtree_random_test(int test_rounds, int key_range,
                                  int add_times, int remove_times,
                                  int shuffle_times);
void           rbtree_key_value_test(int key_count, int tests);
void           rbtree_stress_test(int key_count);

#endif // __RBTREE_H__
