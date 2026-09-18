#ifndef MLDSA_AUTHD_RECOVERY_H
#define MLDSA_AUTHD_RECOVERY_H

#include <stddef.h>
#include <stdint.h>

#include <sodium.h>

#include "base32.h"
#include "store.h"

/*
 * Recovery codes and enrollment tickets (V4-9d), spec mldsa-authd §10.3.
 *
 * A recovery code is 80 bits of entropy the user keeps on paper. The Argon2id
 * hash is NOT what makes it strong -- 80 bits already is -- it is what bounds
 * what a stolen store is worth and what one verification costs the server.
 *
 * WHAT IS HASHED is the CANONICAL base32 string (base32.h), never the raw
 * bytes and never the characters the user happened to type. That choice puts
 * normalisation on the daemon's side of the socket, so a site cannot get it
 * subtly wrong and lock its own users out.
 *
 * THE VERIFICATION LOOP BLOCKS. The daemon is one process, one thread, one
 * poll() loop (V4 decision 2), so recovery_find_match() stops the world for as
 * long as it runs. That is accepted, measured and recorded (V4-9d decision 1),
 * and it is only defensible because the cost is bounded on three sides:
 *   - at most RECOVERY_CODES_MAX unused codes per user, because issuing a new
 *     generation supersedes the previous one (store_recovery_replace);
 *   - at most RECOVERY_LOCK_THRESHOLD attempts before RECOVERY_LOCK_SECONDS of
 *     lockout;
 *   - the lockout is read BEFORE any hashing, so a locked user costs nothing.
 * Remove any one of those and the bound is gone; each has a mutation.
 */

/* Spec §10.3, named rather than written as literals at the call site so
 * tools/audit/check_spec_constants.sh can pin them and so authd_main.c is
 * visibly assigning the spec's numbers. Tests and fuzzing lower the KDF cost
 * through authd_app_t; these are what the daemon itself uses. */
#define RECOVERY_OPS_SPEC       2u                      /* Argon2id opslimit */
#define RECOVERY_MEM_SPEC       (64u * 1024u * 1024u)   /* Argon2id memlimit: 64 MiB */
#define RECOVERY_CODES_MAX      16u                     /* "1..16 codes" */
#define RECOVERY_LOCK_THRESHOLD 5                       /* "five failures" */
#define RECOVERY_LOCK_SECONDS   3600                    /* "...lock for one hour" */
#define RECOVERY_TICKET_TTL_S   600                     /* "valid 10 minutes" */
#define RECOVERY_TICKET_BYTES   32u                     /* opaque, stored hashed */

_Static_assert(RECOVERY_OPS_SPEC == crypto_pwhash_OPSLIMIT_INTERACTIVE,
               "spec §10.3 ops=2 must be libsodium's INTERACTIVE opslimit");
_Static_assert(RECOVERY_MEM_SPEC == crypto_pwhash_MEMLIMIT_INTERACTIVE,
               "spec §10.3 mem=64 MiB must be libsodium's INTERACTIVE memlimit");
_Static_assert(RECOVERY_TICKET_BYTES == STORE_HASH_BYTES,
               "the ticket and its SHA-256 are both 32 bytes; see the note in localapi.c");

/* One fresh code: BASE32_CODE_BYTES of randomness rendered canonically into
 * `code_out`, and its Argon2id hash into `hash_out`. The plaintext exists only
 * in `code_out`, which the caller must wipe once it is in the reply.
 * Returns 0 on success, -1 on argument or KDF failure (both outputs zeroed). */
int recovery_make_code(char code_out[BASE32_CODE_CHARS + 1u],
                       char hash_out[crypto_pwhash_STRBYTES],
                       unsigned long long ops, size_t mem);

/* A fresh ticket and its stored hash. */
void recovery_make_ticket(uint8_t ticket_out[RECOVERY_TICKET_BYTES],
                          uint8_t hash_out[STORE_HASH_BYTES]);

/* Finds the user's unused recovery code matching `typed`, normalising it
 * first. Returns 1 on a match (with *code_id_out set), 0 if none matched, and
 * -1 on a store error or an unnormalisable code.
 *
 * `*tried_out` receives the number of Argon2id verifications actually
 * performed. It exists so a test can assert that a LOCKED user costs zero --
 * a check that cannot be written against the error code alone, because a
 * lockout that is enforced too late returns exactly the same code. */
int recovery_find_match(const store_t *s, const uint8_t *user_id, size_t user_id_len,
                        const char *typed, size_t typed_len,
                        int64_t *code_id_out, size_t *tried_out);

#endif /* MLDSA_AUTHD_RECOVERY_H */
