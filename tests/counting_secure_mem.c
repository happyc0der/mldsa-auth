/*
 * Counting replacement for src/util/secure_mem.c, linked ONLY into
 * test_session_alloc. mldsa_core is a static archive: because this object
 * already defines all three secure_mem_* symbols, the linker never pulls
 * secure_mem.o out of the archive, so every secure allocation made by the
 * library (handshake, kex, mldsa_wrap, session) lands here.
 *
 * Semantics are identical to the real implementation; the only addition is
 * the two counters. test_session_alloc proves the substitution is live
 * (session_init_from_handshake must count exactly one allocation) before
 * trusting any zero it reads.
 */

#include "secure_mem.h"

#include <sodium.h>

size_t counting_secure_mem_allocs = 0;
size_t counting_secure_mem_frees = 0;

void *secure_mem_alloc(size_t len) {
    if (len == 0) {
        return NULL;
    }
    void *p = sodium_malloc(len);
    if (p != NULL) {
        counting_secure_mem_allocs++;
    }
    return p;
}

void secure_mem_wipe(void *ptr, size_t len) {
    if (ptr == NULL || len == 0) {
        return;
    }
    sodium_memzero(ptr, len);
}

void secure_mem_free(void *ptr, size_t len) {
    (void)len;
    if (ptr != NULL) {
        counting_secure_mem_frees++;
        sodium_free(ptr);
    }
}
