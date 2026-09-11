#include "keystore.h"

#include <sodium.h>
#include <string.h>

static int id_len_valid(size_t id_len) {
    return id_len >= WIRE_ID_MIN_LEN && id_len <= WIRE_ID_MAX_LEN;
}

/* Opaque-byte identity comparison: explicit length first, then content.
 * Never treats either side as a C string. */
static int entry_matches(const keystore_entry_t *e, const uint8_t *id, size_t id_len) {
    if (e->id_len == 0 || (size_t)e->id_len != id_len) {
        return 0;
    }
    return sodium_memcmp(e->id, id, id_len) == 0;
}

static keystore_entry_t *find_entry(keystore_t *ks, const uint8_t *id, size_t id_len) {
    for (size_t i = 0; i < KEYSTORE_MAX_ENTRIES; i++) {
        if (entry_matches(&ks->entries[i], id, id_len)) {
            return &ks->entries[i];
        }
    }
    return NULL;
}

void keystore_init(keystore_t *ks) {
    if (ks != NULL) {
        memset(ks, 0, sizeof(*ks));
    }
}

void keystore_wipe(keystore_t *ks) {
    if (ks != NULL) {
        sodium_memzero(ks, sizeof(*ks));
    }
}

keystore_status_t keystore_add(keystore_t *ks, const uint8_t *id, size_t id_len,
                               const uint8_t public_key[MLDSA_PUBLIC_KEY_BYTES]) {
    if (ks == NULL || id == NULL || public_key == NULL || !id_len_valid(id_len)) {
        return KEYSTORE_ERR_INVALID_ARG;
    }

    keystore_entry_t *existing = find_entry(ks, id, id_len);
    if (existing != NULL) {
        if (sodium_memcmp(existing->public_key, public_key, MLDSA_PUBLIC_KEY_BYTES) == 0) {
            return KEYSTORE_OK_ALREADY_PRESENT;
        }
        /* A different key for a pinned identity is never accepted and never
         * replaces the pin (Security Req 4.7). */
        return KEYSTORE_ERR_KEY_MISMATCH;
    }

    if (ks->count >= KEYSTORE_MAX_ENTRIES) {
        return KEYSTORE_ERR_FULL;
    }
    for (size_t i = 0; i < KEYSTORE_MAX_ENTRIES; i++) {
        keystore_entry_t *e = &ks->entries[i];
        if (e->id_len == 0) {
            memcpy(e->id, id, id_len);
            e->id_len = (uint8_t)id_len;
            memcpy(e->public_key, public_key, MLDSA_PUBLIC_KEY_BYTES);
            ks->count++;
            return KEYSTORE_OK;
        }
    }
    return KEYSTORE_ERR_FULL; /* unreachable while count is consistent */
}

keystore_status_t keystore_lookup(const keystore_t *ks, const uint8_t *id, size_t id_len,
                                  const uint8_t **public_key_out) {
    if (public_key_out == NULL) {
        return KEYSTORE_ERR_INVALID_ARG;
    }
    *public_key_out = NULL;
    if (ks == NULL || id == NULL || !id_len_valid(id_len)) {
        return KEYSTORE_ERR_INVALID_ARG;
    }

    for (size_t i = 0; i < KEYSTORE_MAX_ENTRIES; i++) {
        if (entry_matches(&ks->entries[i], id, id_len)) {
            *public_key_out = ks->entries[i].public_key;
            return KEYSTORE_OK;
        }
    }
    return KEYSTORE_ERR_NOT_FOUND;
}

size_t keystore_count(const keystore_t *ks) {
    return (ks != NULL) ? ks->count : 0;
}
