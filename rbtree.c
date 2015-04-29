#include "rbtree.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

rbtree_node_t *rbtree_new_node(int key, void *data, int color)
{
    rbtree_node_t *ret = (rbtree_node_t *)malloc(sizeof(rbtree_node_t));
    ret->key = key;
    ret->data = data;
    ret->color = color;
    ret->parent = NULL;
    ret->left = NULL;
    ret->right = NULL;
    return ret;
}

void rbtree_free_node(rbtree_node_t *n)
{
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

rbtree_node_t *rbtree_init()
{
    return 0;
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

rbtree_node_t *rbtree_insert(rbtree_node_t *root, int key, void *data)
{
    rbtree_node_t *new_node = rbtree_new_node(key, data, RBTREE_RED);
    if(root == NULL) {
        new_node->color = RBTREE_BLACK;
        return new_node;
    }

    rbtree_node_t *p = root, *s = NULL;
    while(p) {
        s = p;
        if(new_node->key < p->key)
            p = p->left;
        else
            p = p->right;
    }

    if(new_node->key < s->key) {
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

    return rbtree_insert_adjust(root, s);
}

rbtree_node_t *rbtree_find_node(rbtree_node_t *root, int key)
{
    rbtree_node_t *p = root;
    while(p && p->key != key) {
        if(p->key < key)
            p = p->right;
        else
            p = p->left;
    }
    return p;
}

void rbtree_swap_node(rbtree_node_t *a, rbtree_node_t *b)
{
    rbtree_node_t tmp;
    tmp.key = a->key;
    a->key = b->key;
    b->key = tmp.key;
    tmp.data = a->data;
    a->data = b->data;
    b->data = tmp.data;
}

void rbtree_copy_node(rbtree_node_t *dst, rbtree_node_t *src)
{
    dst->key = src->key;
    dst->data = src->data;
}

rbtree_node_t *rbtree_remove_fix_consecutive_red(
    rbtree_node_t *root, rbtree_node_t *n)
{
    printf("rbtree_remove_fix_consecutive_red on node %d\n", n->key);
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
    printf("rbtree_remove_fix_negative_red on node %d\n", n->key);
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
        printf("rbtree_remove_bubble_up on node %d\n", parent->key);
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
    printf("rbtree_remove_adjust on node %d\n", node->key);
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

rbtree_node_t *rbtree_remove(rbtree_node_t *root, int key)
{
    rbtree_node_t *p = rbtree_find_node(root, key), *s, *new_root;
    if(!p) return root;

    if(p->right && p->left) {
        s = p->right;
        while(s->left) s = s->left;
        rbtree_copy_node(p, s);
        new_root = rbtree_remove_adjust(root, s);
        free(s);
    } else {
        new_root = rbtree_remove_adjust(root, p);
        free(p);
    }
    return new_root;
}

void *rbtree_find(rbtree_node_t *root, int key)
{
    rbtree_node_t *p = rbtree_find_node(root, key);
    if(p)
        return p->data;
    return NULL;
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
    printf("%d:%s\n", n->key, rbtree_color_to_string(n->color));
    rbtree_print_with_depth(n->left, depth + 1);
    rbtree_print_with_depth(n->right, depth + 1);
}

void rbtree_print(rbtree_node_t *root)
{
    rbtree_print_with_depth(root, 0);
}

void rbtree_free(rbtree_node_t *root)
{
    if(!root) return ;
    rbtree_free(root->left);
    rbtree_free(root->right);
    rbtree_free_node(root);
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

    if(cnt_left != cnt_right) {
        assert(0 && "rbtree_check_node_properties: unbalanced black child nodes");
        return -1;
    }
    return cnt_left + cnt_right + (n->color == RBTREE_BLACK) ? 1 : 0;
}

int rbtree_validate(rbtree_node_t *root)
{
    if(!root) return 0;
    if(root->color != RBTREE_BLACK) {
        assert(0 && "rbtree_validate: root is red");
        return -1;
    }
    return rbtree_check_node_properties(root);
}

void rbtree_random_test(int test_rounds, int key_range, int add_times,
                        int remove_times, int shuffle_times)
{
    rbtree_node_t *root;
    int keys[RBTREE_TEST_MAX_KEY], key_cnt = 0, i, j, k, x, y;

    assert(add_times <= RBTREE_TEST_MAX_KEY && "too many keys");
    for(i = 0; i < test_rounds; i++) {
        key_cnt = 0;
        printf("round #%d\n", i + 1);
        root = rbtree_init();
        for(j = 0; j < add_times; j++) {
            k = rand() % key_range;
            printf("inserting %d...\n", k);
            root = rbtree_insert(root, k, 0);
            rbtree_validate(root);
            keys[key_cnt++] = k;
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
            root = rbtree_remove(root, keys[j]);
            rbtree_validate(root);
        }
        rbtree_free(root);
    }
}

unsigned int rbtree_hash_string(const char *s)
{
    unsigned int seed = 131;
    unsigned int hash = 0;
    size_t length = strlen(s), i;

    for(i = 0; i < length; i++) {
        hash = (hash * seed) + s[i];
    }

    return (hash & 0x7FFFFFFF);
}

struct key_value_pair_t {
    char key[11];
    char value[11];

    struct key_value_pair_t *next;
};

void rbtree_key_value_test(int key_count, int tests)
{
    int i, j, c;
    rbtree_t root = rbtree_init();
    struct key_value_pair_t pairs[RBTREE_TEST_MAX_KEY];
    for(i = 0; i < key_count; i++) {
        for(j = 0; j < 10; j++) {
            c = rand() % 52;
            pairs[i].key[j] = (c >= 26) ? (c - 26) + 'A' : c + 'a';
            c = rand() % 52;
            pairs[i].value[j] = (c >= 26) ? (c - 26) + 'A' : c + 'a';
        }
        pairs[i].key[j] = '\0';
        pairs[i].value[j] = '\0';
        pairs[i].next = NULL;

        unsigned int hash = rbtree_hash_string(pairs[i].key);
        printf("adding %s=%s (hash %d) to set\n",
            pairs[i].key, pairs[i].value, hash);
        struct key_value_pair_t *ptr = rbtree_find(root, hash);
        if(ptr) {
            puts("warning: string hash nested");
            while(ptr->next) ptr = ptr->next;
            ptr->next = &pairs[i];
        } else {
            root = rbtree_insert(root, hash, &pairs[i]);
        }
    }
    puts("insertion done");
    for(i = 0; i < tests; i++) {
        j = rand() % key_count;
        unsigned int hash = rbtree_hash_string(pairs[j].key);
        struct key_value_pair_t *ptr = rbtree_find(root, hash);
        assert(ptr && "key not found");
        while(ptr) {
            if(strcmp(ptr->key, pairs[j].key) == 0) break;
        }
        assert(ptr && "data retrieved but key not found");
        assert(!strcmp(ptr->value, pairs[j].value) && "value not match");
        printf("value located: %s = %s\n", ptr->key, ptr->value);
    }
}

void rbtree_stress_test(int key_count)
{
    rbtree_t root = rbtree_init();
    int i;
    clock_t begin = clock();
    for(i = 0; i < key_count; i++) {
        root = rbtree_insert(root, rand(), 0);
    }
    clock_t end = clock();
    printf("%d insertion cost %.2f sec\n", key_count,
        (float)(end - begin) / CLOCKS_PER_SEC);

    begin = clock();
    for(i = 0; i < key_count; i++) {
        rbtree_find(root, rand());
    }
    end = clock();
    printf("%d retrival cost %.2f sec\n", key_count,
        (float)(end - begin) / CLOCKS_PER_SEC);
}
