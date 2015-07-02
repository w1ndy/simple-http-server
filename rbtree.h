#ifndef __RBTREE_H__
#define __RBTREE_H__

#define RBTREE_NEGRED   -1
#define RBTREE_RED      0
#define RBTREE_BLACK    1
#define RBTREE_DBLBLACK 2

#define RBTREE_TEST_MAX_KEY 5000

typedef int (*compfunc_t)(const void *a, const void *b);

typedef struct tag_rbtree_node
{
    void *data;
    int color;
    struct tag_rbtree_node *parent;
    struct tag_rbtree_node *left;
    struct tag_rbtree_node *right;
} rbtree_node_t;

typedef struct tag_rbtree_t
{
    compfunc_t compfunc;
    rbtree_node_t *root;
} rbtree_t;

rbtree_t      *rbtree_init(compfunc_t cf);
void          *rbtree_insert(rbtree_t *tree, void *data);
void           rbtree_remove(rbtree_t *tree, const void *data);
rbtree_node_t *rbtree_new_node(void *data, int color);
int            rbtree_validate(rbtree_t *tree);
int            rbtree_is_empty(rbtree_t *tree);
rbtree_node_t *rbtree_find_node(rbtree_t *tree, const void *data);
void          *rbtree_find(rbtree_t *tree, const void *data);
void          *rbtree_find_max(rbtree_t *tree);
void          *rbtree_find_min(rbtree_t *tree);
void           rbtree_free(rbtree_t *tree);
void           rbtree_print(rbtree_t *tree);

unsigned int   rbtree_hash_string(const char *s);
unsigned int   rbtree_hash_mem(const unsigned char *s, unsigned int size);

void           rbtree_random_test(int test_rounds, int key_range,
                                  int add_times, int remove_times,
                                  int shuffle_times);
void           rbtree_stress_test(int key_count);

#endif // __RBTREE_H__
