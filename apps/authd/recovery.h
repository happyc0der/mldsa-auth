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
 *   - since V4-76 (F143), ONE Argon2id computation per attempt, whatever the
 *     user's state: every code of a generation shares its salt, so the typed
 *     code is hashed once and compared with all of them, and a refusal that
 *     has no code to hash against (an unknown, disabled, locked or operator
 *     user, or a typed string that is not a code) spends one computation
 *     anyway. Until then the time of a refusal was one computation per
 *     unused code, and nothing for an unknown user: one request told anyone
 *     whether a username existed and how many codes it had.
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
/* V4-78 (F155): RECOVERY-USE on site.sock, daemon-wide, before any hashing. F143
 * made every refusal cost one Argon2id computation, which removed the bound the
 * lockout had given: a made-up username never locks. This restores one: at most
 * RECOVERY_USE_BURST attempts at once and RECOVERY_USE_PER_SEC a second, about
 * 9% of one core at the spec's cost; past it the answer is `busy`, at no cost
 * and the same whoever is named. admin.sock is not counted. */
#define RECOVERY_USE_PER_SEC    2u
#define RECOVERY_USE_BURST      4u

_Static_assert(RECOVERY_OPS_SPEC == crypto_pwhash_OPSLIMIT_INTERACTIVE,
               "spec §10.3 ops=2 must be libsodium's INTERACTIVE opslimit");
_Static_assert(RECOVERY_MEM_SPEC == crypto_pwhash_MEMLIMIT_INTERACTIVE,
               "spec §10.3 mem=64 MiB must be libsodium's INTERACTIVE memlimit");
_Static_assert(RECOVERY_TICKET_BYTES == STORE_HASH_BYTES,
               "the ticket and its SHA-256 are both 32 bytes; see the note in localapi.c");

/* A generation's salt: every code issued together shares it (F143). */
void recovery_new_salt(uint8_t salt[crypto_pwhash_SALTBYTES]);

/* One fresh code: BASE32_CODE_BYTES of randomness rendered canonically into
 * `code_out`, and its stored form into `hash_out`:
 * "$mrc1$<ops>$<mem>$<salt hex>$<Argon2id13 hash hex>". The plaintext exists
 * only in `code_out`, which the caller must wipe once it is in the reply.
 * Returns 0 on success, -1 on argument or KDF failure (both outputs zeroed). */
int recovery_make_code(char code_out[BASE32_CODE_CHARS + 1u],
                       char hash_out[crypto_pwhash_STRBYTES],
                       const uint8_t salt[crypto_pwhash_SALTBYTES],
                       unsigned long long ops, size_t mem);

/* One Argon2id computation at `ops`/`mem`, its result discarded: what a
 * refusal that has nothing to verify spends, so that it takes as long as one
 * that has (F143). */
void recovery_spend_one(unsigned long long ops, size_t mem);

/* A fresh ticket and its stored hash. */
void recovery_make_ticket(uint8_t ticket_out[RECOVERY_TICKET_BYTES],
                          uint8_t hash_out[STORE_HASH_BYTES]);

/* Finds the user's unused recovery code matching `typed`, normalising it
 * first. Returns 1 on a match (with *code_id_out set), 0 if none matched or
 * `typed` is not a code, and -1 on a store error.
 *
 * `*tried_out` receives the number of Argon2id computations actually
 * performed: one per generation of codes (one, once re-issuing has
 * superseded the last), one per code issued before V4-76, and one -- at
 * `ops`/`mem` -- when there is nothing to hash against. It exists so a test
 * can assert the cost of every kind of refusal, which the error code alone
 * cannot show. */
int recovery_find_match(const store_t *s, const uint8_t *user_id, size_t user_id_len,
                        const char *typed, size_t typed_len,
                        unsigned long long ops, size_t mem,
                        int64_t *code_id_out, size_t *tried_out);

#endif /* MLDSA_AUTHD_RECOVERY_H */
