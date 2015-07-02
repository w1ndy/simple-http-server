#include "rbtree.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <memory.h>

#include "bufferpool.h"

rbtree_node_t *rbtree_new_node(void *data, int color)
{
    rbtree_node_t *ret = (rbtree_node_t *)malloc(sizeof(rbtree_node_t));
    ret->data = data;
    ret->color = color;

    ret->parent = NULL;
    ret->left = NULL;
    ret->right = NULL;

    return ret;
}

void rbtree_free_node(rbtree_node_t *n)
{
    if(n->left)
        rbtree_free_node(n->left);
    if(n->right)
        rbtree_free_node(n->right);
    free(n);
}

rbtree_node_t *rbtree_get_grandparent(rbtree_node_t *node)
{
    if(node && node->parent)
        return node->parent->parent;
    return NULL;
}

rbtree_node_t *rbtree_get_uncle(rbtree_node_t *node)
{
    rbtree_node_t *grandparent = rbtree_get_grandparent(node);
    if(!grandparent)
        return NULL;
    if(node->parent == grandparent->left)
        return grandparent->right;
    return grandparent->left;
}

rbtree_node_t *rbtree_get_sibling(rbtree_node_t *node)
{
    if(node->parent) {
        if(node->parent->left == node)
            return node->parent->right;
        else
            return node->parent->left;
    }
    return NULL;
}

rbtree_t *rbtree_init(compfunc_t cf)
{
    rbtree_t *t = (rbtree_t*)malloc(sizeof(rbtree_t));
    t->compfunc = cf;
    t->root = NULL;
    return t;
}

void rbtree_rotate_left(rbtree_node_t *node)
{
    rbtree_node_t *p = node->right;
    node->right = p->left;
    if(p->left) p->left->parent = node;
    p->parent = node->parent;
    if(node->parent) {
        if(node->parent->left == node)
            node->parent->left = p;
        else
            node->parent->right = p;
    }
    node->parent = p;
    p->left = node;
}

void rbtree_rotate_right(rbtree_node_t *node)
{
    rbtree_node_t *p = node->left;
    node->left = p->right;
    if(p->right) p->right->parent = node;
    p->parent = node->parent;
    if(node->parent) {
        if(node->parent->left == node)
            node->parent->left = p;
        else
            node->parent->right = p;
    }
    node->parent = p;
    p->right = node;
}

rbtree_node_t *rbtree_insert_adjust(rbtree_node_t *root, rbtree_node_t *node)
{
    if(node->parent == NULL) {
        node->color = RBTREE_BLACK;
        return node;
    }

    if(node->parent->color == RBTREE_BLACK)
        return root;

    rbtree_node_t *uncle = rbtree_get_uncle(node),
                  *grandparent = rbtree_get_grandparent(node);
    if(uncle && uncle->color == RBTREE_RED) {
        node->parent->color = RBTREE_BLACK;
        uncle->color = RBTREE_BLACK;
        grandparent->color = RBTREE_RED;
        return rbtree_insert_adjust(root, grandparent);
    }

    if(grandparent) {
        if(node == node->parent->right &&
                node->parent == grandparent->left) {
            rbtree_rotate_left(node->parent);
            node = node->left;
        } else if(node == node->parent->left &&
                node->parent == grandparent->right) {
            rbtree_rotate_right(node->parent);
            node = node->right;
        }
        node->parent->color = RBTREE_BLACK;
        grandparent->color = RBTREE_RED;
        if(node == node->parent->left)
            rbtree_rotate_right(grandparent);
        else
            rbtree_rotate_left(grandparent);
        if(node->parent->parent == NULL)
            return node->parent;
    }
    return root;
}

void *rbtree_insert(rbtree_t *tree, void *data)
{
    if(tree->root == NULL) {
        tree->root = rbtree_new_node(data, RBTREE_BLACK);
        return NULL;
    }

    int cr;
    rbtree_node_t *p = tree->root, *s = NULL;

    while(p) {
        s = p;
        cr = tree->compfunc(data, p->data);
        if(cr < 0)
            p = p->left;
        else if(cr > 0)
            p = p->right;
        else {
            void *old = p->data;
            p->data = data;
            return old;
        }
    }

    rbtree_node_t *new_node = rbtree_new_node(data, RBTREE_RED);
    if(cr < 0) {
        s->left = new_node;
        p = s;
        s = s->left;
        s->parent = p;
    } else {
        s->right = new_node;
        p = s;
        s = s->right;
        s->parent = p;
    }

    tree->root = rbtree_insert_adjust(tree->root, s);
    return NULL;
}

rbtree_node_t *rbtree_find_node(rbtree_t *tree, const void *data)
{
    rbtree_node_t *p = tree->root;
    int cr;
    while(p) {
        cr = tree->compfunc(data, p->data);
        if(cr > 0) p = p->right;
        else if(cr < 0) p = p->left;
        else return p;
    }
    return NULL;
}

void rbtree_swap_node(rbtree_node_t *a, rbtree_node_t *b)
{
    rbtree_node_t tmp;
    tmp.data = a->data;
    a->data = b->data;
    b->data = tmp.data;
}

void rbtree_copy_node(rbtree_node_t *dst, rbtree_node_t *src)
{
    dst->data = src->data;
}

rbtree_node_t *rbtree_remove_fix_consecutive_red(
    rbtree_node_t *root, rbtree_node_t *n)
{
    //printf("rbtree_remove_fix_consecutive_red on node %d\n", n->key);
    rbtree_node_t *grandparent = rbtree_get_grandparent(n);
    rbtree_node_t *new_root = root, *top;

    if(!grandparent) {
        n->parent->color = RBTREE_BLACK;
        return n->parent;
    }

    if(n == n->parent->right && n->parent == grandparent->left) {
        rbtree_rotate_left(n->parent);
        top = n;
    } else if(n == n->parent->left && n->parent == grandparent->right) {
        rbtree_rotate_right(n->parent);
        top = n;
    } else {
        top = n->parent;
    }

    if(grandparent == root)
        new_root = top;

    if(top == grandparent->left)
        rbtree_rotate_right(grandparent);
    else
        rbtree_rotate_left(grandparent);

    top->color = grandparent->color - 1;
    top->left->color = RBTREE_BLACK;
    top->right->color = RBTREE_BLACK;

    new_root->parent = NULL;
    if(top == new_root)
        new_root->color = RBTREE_BLACK;
    else if(top->color == RBTREE_RED && top->parent->color == RBTREE_RED)
        rbtree_remove_fix_consecutive_red(root, top);
    return new_root;
}

rbtree_node_t *rbtree_remove_fix_negative_red(
    rbtree_node_t *root, rbtree_node_t *n)
{
    //printf("rbtree_remove_fix_negative_red on node %d\n", n->key);
    rbtree_node_t *n1, *n2, *n3, *n4, *t1, *t2, *t3;
    rbtree_node_t *child, *parent = n->parent;
    if(parent->left == n) {
        n1 = n->left;
        n2 = n;
        n3 = n->right;
        n4 = parent;
        t1 = n3->left;
        t2 = n3->right;
        t3 = n4->right;
        n1->color = RBTREE_RED;
        n2->color = RBTREE_BLACK;
        n4->color = RBTREE_BLACK;

        n2->right = t1;
        if(t1) t1->parent = n2;
        rbtree_swap_node(n4, n3);
        n3->left = t2;
        if(t2) t2->parent = n3;
        n3->right = t3;
        if(t3) t3->parent = n3;
        n4->right = n3;
        n3->parent = n4;
        child = n1;
    } else {
        n4 = n->right;
        n3 = n;
        n2 = n->left;
        n1 = parent;
        t3 = n2->right;
        t2 = n2->left;
        t1 = n1->left;
        n4->color = RBTREE_RED;
        n3->color = RBTREE_BLACK;
        n1->color = RBTREE_BLACK;

        n3->left = t3;
        if(t3) t3->parent = n3;
        rbtree_swap_node(n1, n2);
        n2->right = t2;
        if(t2) t2->parent = n2;
        n2->left = t1;
        if(t1) t1->parent = n2;
        n1->left = n2;
        n2->parent = n1;
        child = n4;
    }

    if(child->left && child->left->color == RBTREE_RED) {
        return rbtree_remove_fix_consecutive_red(root, child->left);
    }
    if(child->right && child->right->color == RBTREE_RED) {
        return rbtree_remove_fix_consecutive_red(root, child->right);
    }
    return root;
}

rbtree_node_t *rbtree_remove_bubble_up(
    rbtree_node_t *root, rbtree_node_t *parent)
{
    while(parent) {
        //printf("rbtree_remove_bubble_up on node %d\n", parent->key);
        parent->color++;
        parent->left->color--;
        parent->right->color--;

        rbtree_node_t *child = parent->left;
        switch(child->color) {
            case RBTREE_NEGRED:
                return rbtree_remove_fix_negative_red(root, child);
            case RBTREE_RED:
                if(child->left && child->left->color == RBTREE_RED) {
                    return rbtree_remove_fix_consecutive_red(
                        root, child->left);
                }
                if(child->right && child->right->color == RBTREE_RED) {
                    return rbtree_remove_fix_consecutive_red(
                        root, child->right);
                }
                break;
        }

        child = parent->right;
        switch(child->color) {
            case RBTREE_NEGRED:
                return rbtree_remove_fix_negative_red(root, child);
            case RBTREE_RED:
                if(child->left && child->left->color == RBTREE_RED) {
                    return rbtree_remove_fix_consecutive_red(
                        root, child->left);
                }
                if(child->right && child->right->color == RBTREE_RED) {
                    return rbtree_remove_fix_consecutive_red(
                        root, child->right);
                }
                break;
        }

        if(parent->color == RBTREE_DBLBLACK) {
            if(parent->parent)
                parent = parent->parent;
            else {
                parent->color = RBTREE_BLACK;
                return parent;
            }
        } else break;
    }
    return root;
}

rbtree_node_t *rbtree_remove_adjust(rbtree_node_t *root, rbtree_node_t *node)
{
    //printf("rbtree_remove_adjust on node %d\n", node->key);
    rbtree_node_t *child = (node->left) ? node->left : node->right;
    rbtree_node_t *new_root;

    if(node->parent == NULL) {
        if(child) {
            child->parent = NULL;
            child->color = RBTREE_BLACK;
        }
        return child;
    }

    if(node->color == RBTREE_RED) {
        new_root = root;
    } else if(child) {
        child->color = RBTREE_BLACK;
        new_root = root;
    } else {
        new_root = rbtree_remove_bubble_up(root, node->parent);
    }

    if(node->parent->left == node)
        node->parent->left = child;
    else
        node->parent->right = child;
    if(child)
        child->parent = node->parent;
    return new_root;
}

void rbtree_remove(rbtree_t *tree, const void *data)
{
    assert(tree && "tree is null");
    rbtree_node_t *p = rbtree_find_node(tree, data), *s;
    if(!p) return ;

    if(p->right && p->left) {
        s = p->right;
        while(s->left) s = s->left;
        rbtree_copy_node(p, s);
        tree->root = rbtree_remove_adjust(tree->root, s);
        free(s);
    } else {
        tree->root = rbtree_remove_adjust(tree->root, p);
        free(p);
    }
}

void *rbtree_find(rbtree_t *tree, const void *data)
{
    rbtree_node_t *p = rbtree_find_node(tree, data);
    return p ? p->data : NULL;
}

const char *rbtree_color_to_string(int color)
{
    switch(color)
    {
        case RBTREE_RED: return "RED";
        case RBTREE_BLACK: return "BLACK";
    }
    return "INVALID";
}

void rbtree_print_with_depth(rbtree_node_t *n, int depth)
{
    int d;
    if(!n) {
        for(d = 0; d < depth; d++)
            putchar(' ');
        puts("Nil");
        return ;
    }

    for(d = 0; d < depth; d++)
        putchar(' ');
    //printf("%d:%s\n", n->key, rbtree_color_to_string(n->color));
    rbtree_print_with_depth(n->left, depth + 1);
    rbtree_print_with_depth(n->right, depth + 1);
}

void rbtree_print(rbtree_t *tree)
{
    rbtree_print_with_depth(tree->root, 0);
}

void rbtree_free(rbtree_t *tree)
{
    if(tree->root)
        rbtree_free_node(tree->root);
    free(tree);
}

int rbtree_check_node_properties(rbtree_node_t *n)
{
    if(n == NULL) return 1;

    if(n->color != RBTREE_BLACK && n->color != RBTREE_RED) {
        assert(0 && "rbtree_check_node_properties: invalid color");
        return -1;
    }
    if(n->color == RBTREE_RED) {
        if(n->parent->color != RBTREE_BLACK ||
                (n->left && n->left->color != RBTREE_BLACK) ||
                (n->right && n->right->color != RBTREE_BLACK)) {
            assert(0 && "rbtree_check_node_properties: consecutive red node");
            return -1;
        }
    }
    assert((n->left == NULL || n->left->parent == n) && "left child with improperly set parent pointer");
    int cnt_left = rbtree_check_node_properties(n->left);
    if(cnt_left == -1) return -1;

    assert((n->right == NULL || n->right->parent == n) && "right child with improperly set parent pointer");
    int cnt_right = rbtree_check_node_properties(n->right);
    if(cnt_right == -1) return -1;

    assert(cnt_left == cnt_right && "rbtree_check_node_properties: unbalanced black child nodes");
    return cnt_left + cnt_right + (n->color == RBTREE_BLACK) ? 1 : 0;
}

int rbtree_validate(rbtree_t *tree)
{
    assert(tree && "tree is null");
    if(!tree->root) return 0;
    assert(tree->root->color == RBTREE_BLACK
        && "rbtree_validate: root is red");
    return rbtree_check_node_properties(tree->root);
}

int rbtree_is_empty(rbtree_t *tree)
{
    return (tree->root == NULL);
}

void *rbtree_find_max(rbtree_t *tree)
{
    rbtree_node_t *p = tree->root;
    while(p && p->right) p = p->right;
    return p ? p->data : NULL;
}

void *rbtree_find_min(rbtree_t *tree)
{
    rbtree_node_t *p = tree->root;
    while(p && p->left) p = p->left;
    return p ? p->data : NULL;
}

void rbtree_random_test(int test_rounds, int key_range, int add_times,
                        int remove_times, int shuffle_times)
{
    rbtree_t *tree;
    int keys[RBTREE_TEST_MAX_KEY], key_cnt = 0, i, j, k, x, y;

    int intcompfunc(const void *a, const void *b) {
        const int *ia = (const int *)a;
        const int *ib = (const int *)b;
        if(*ia < *ib) return -1;
        else if(*ia > *ib) return 1;
        else return 0;
    }

    assert(add_times <= RBTREE_TEST_MAX_KEY && "too many keys");
    for(i = 0; i < test_rounds; i++) {
        key_cnt = 0;
        printf("round #%d\n", i + 1);
        tree = rbtree_init(intcompfunc);
        for(j = 0; j < add_times; j++) {
            k = rand() % key_range;
            printf("inserting %d...\n", k);
            keys[key_cnt++] = k;
            rbtree_insert(tree, &keys[key_cnt - 1]);
            rbtree_validate(tree);
        }
        for(j = 0; j < shuffle_times; j++) {
            x = rand() % key_cnt;
            y = rand() % key_cnt;
            k = keys[x];
            keys[x] = keys[y];
            keys[y] = k;
        }
        for(j = 0; j < remove_times; j++) {
            printf("removing %d...\n", keys[j]);
            rbtree_remove(tree, &keys[j]);
            rbtree_validate(tree);
        }
        rbtree_free(tree);
    }
}

unsigned int rbtree_hash_string(const char *s)
{
    return rbtree_hash_mem((const unsigned char *)s, strlen(s));
}

unsigned int rbtree_hash_mem(const unsigned char *s, unsigned int size)
{
    unsigned int seed = 131;
    unsigned int hash = 0;
    unsigned int i;

    for(i = 0; i < size; i++) {
        hash = (hash * seed) + s[i];
    }

    return (hash & 0x7FFFFFFF);
}

void rbtree_stress_test(int key_count)
{
    struct tag_rbtest_item {
        int value;
    };

    int compfunc(const void *a, const void *b)
    {
        struct tag_rbtest_item *tria = (struct tag_rbtest_item *) a;
        struct tag_rbtest_item *trib = (struct tag_rbtest_item *) b;
        if(tria->value < trib->value) return -1;
        else return (tria->value == trib->value) ? 0 : 1;
    }

    rbtree_t *tree = rbtree_init(compfunc);
    int i;
    bufferpool_t *pool = bufferpool_create(sizeof(struct tag_rbtest_item));

    clock_t begin = clock();
    for(i = 0; i < key_count; i++) {
        printf("inserting #%d\n", i);
        struct tag_rbtest_item *item = bufferpool_alloc(pool);
        item->value = rand();
        rbtree_insert(tree, item);
    }
    clock_t end = clock();
    printf("%d insertion cost %.2f sec\n", key_count,
        (float)(end - begin) / CLOCKS_PER_SEC);

    struct tag_rbtest_item search_key;
    begin = clock();
    for(i = 0; i < key_count; i++) {
        search_key.value = rand();
        rbtree_find(tree, &search_key);
    }
    end = clock();
    printf("%d retrival cost %.2f sec\n", key_count,
        (float)(end - begin) / CLOCKS_PER_SEC);
    bufferpool_free(pool, 1);
}
