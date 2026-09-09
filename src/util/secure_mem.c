#include "secure_mem.h"

#include <sodium.h>

void *secure_mem_alloc(size_t len) {
    if (len == 0) {
        return NULL;
    }
    return sodium_malloc(len);
}

void secure_mem_wipe(void *ptr, size_t len) {
    if (ptr == NULL || len == 0) {
        return;
    }
    sodium_memzero(ptr, len);
}

void secure_mem_free(void *ptr, size_t len) {
    (void)len; /* sodium_free() knows the allocation's real size and
                * always zeroes it before releasing the memory. */
    if (ptr != NULL) {
        sodium_free(ptr);
    }
}
