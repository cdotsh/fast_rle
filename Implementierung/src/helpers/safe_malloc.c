#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

void *safe_malloc(size_t len) {
    void *ret_val = malloc(len);
    if (!ret_val) {
        printf("malloc failed");
        exit(1);
    }
    return ret_val;
}

void *safe_calloc(size_t amount, size_t size) {
    void *ret_val = calloc(amount, size);
    if (!ret_val) {
        printf("calloc failed");
        exit(1);
    }
    return ret_val;
}

void *safe_realloc(void *old_ptr, size_t new_size) {
    void *new_ptr = realloc(old_ptr, new_size);
    if (!new_ptr) {
        printf("realloc failed");
        exit(1);
    }
    return new_ptr;
}
