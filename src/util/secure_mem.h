#ifndef MLDSA_AUTH_UTIL_SECURE_MEM_H
#define MLDSA_AUTH_UTIL_SECURE_MEM_H

#include <stddef.h>

/*
 * Thin wrappers over libsodium's secure allocator (sodium_malloc /
 * sodium_free / sodium_memzero) for private keys, shared secrets, and
 * session keys (Security Requirement 4.2). Every buffer obtained from
 * secure_mem_alloc() must be released via secure_mem_free() on every exit
 * path, including error returns -- there is no implicit cleanup.
 */

/* Allocates `len` bytes of secret-material storage via sodium_malloc.
 * Returns NULL on failure (len == 0, or the underlying allocation
 * failed). The returned memory's contents are unspecified -- callers
 * that need it zeroed must do so themselves. */
void *secure_mem_alloc(size_t len);

/* Wipes `len` bytes at `ptr`. No-op if ptr is NULL. Safe to call on any
 * memory holding secret material, not just secure_mem_alloc'd buffers --
 * e.g. stack-allocated scratch buffers that briefly held key material. */
void secure_mem_wipe(void *ptr, size_t len);

/* Wipes and frees memory obtained from secure_mem_alloc(). No-op if ptr
 * is NULL. `len` is accepted for API symmetry with secure_mem_alloc /
 * secure_mem_wipe, but sodium_free() tracks and zeroes the allocation's
 * actual size internally regardless. */
void secure_mem_free(void *ptr, size_t len);

#endif /* MLDSA_AUTH_UTIL_SECURE_MEM_H */
