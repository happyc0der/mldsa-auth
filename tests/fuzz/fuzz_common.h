#ifndef MLDSA_AUTH_FUZZ_COMMON_H
#define MLDSA_AUTH_FUZZ_COMMON_H

/*
 * Shared infrastructure for the Step 7 fuzz targets (tests/fuzz/).
 *
 * DETERMINISTIC RNG -- TEST ONLY. fuzz_common_init() replaces libsodium's
 * and liboqs's randomness with a fixed-key ChaCha20 stream, so every key,
 * ephemeral, nonce and signature a harness produces is identical from run
 * to run. This makes corpus seeds stay valid, crashes reproduce exactly, and
 * lets oracles compare against genuine bytes regenerated at runtime. It is
 * linked ONLY into fuzz binaries; production code never sees it.
 *
 * REPOSITORY SECRET POLICY: no ML-DSA secret key bytes -- including these
 * deterministic fixture keys -- are ever committed to corpus, regression,
 * dictionary, artifact or source files. Fixture secrets exist only in memory
 * (and, for fuzz_keys, briefly in a 0600 temp file under $TMPDIR).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "handshake.h"
#include "keystore.h"
#include "mldsa_wrap.h"
#include "session.h"
#include "transcript.h"

/* ---- oracles ------------------------------------------------------------ */

#define FUZZ_ASSERT(cond, msg)                              \
    do {                                                    \
        if (!(cond)) {                                      \
            fuzz_fail(__FILE__, __LINE__, #cond, (msg));    \
        }                                                   \
    } while (0)

_Noreturn void fuzz_fail(const char *file, int line, const char *cond, const char *msg);

/* Set by the replay driver when reproducing individual files (extra logging). */
extern int fuzz_verbose;

/* Optional hook, set by the replay driver: called by fuzz_fail() before
 * abort() so the failing input is saved as a crash-* artifact (in the
 * current directory -- the ignored build directory under CTest). libFuzzer
 * saves its own artifacts, so the libFuzzer binaries leave this NULL. */
extern void (*fuzz_failure_hook)(void);

/* ---- zero-length safety --------------------------------------------------- */

/* Non-NULL storage for every zero-length argument passed to a library API. */
extern const uint8_t fuzz_empty[1];

/* data[0], or `fallback` when size == 0. The ONLY way harnesses read byte 0. */
uint8_t fuzz_selector(const uint8_t *data, size_t size, uint8_t fallback);

/* The bytes after the selector: (data + 1, size - 1), or (fuzz_empty, 0). */
void fuzz_payload(const uint8_t *data, size_t size, const uint8_t **p, size_t *n);

/* `data` itself, or fuzz_empty when size == 0 (never NULL). */
const uint8_t *fuzz_ptr(const uint8_t *data, size_t size);

/* ---- deterministic randomness (TEST ONLY) --------------------------------- */

enum {
    FUZZ_STREAM_IDENTITY_A = 1, /* alice's ML-DSA keypair */
    FUZZ_STREAM_IDENTITY_B = 2, /* bob's ML-DSA keypair */
    FUZZ_STREAM_HANDSHAKE = 3   /* everything a per-input handshake consumes */
};

/* Installs the RNG hooks (before sodium_init), runs sodium_init, prints the
 * DETERMINISTIC RNG banner once, and builds the shared identities. Idempotent. */
void fuzz_common_init(void);

/* Restarts the given deterministic stream from its beginning. */
void fuzz_rng_reset_stream(uint32_t stream);

/* fuzz_rng_reset_stream(FUZZ_STREAM_HANDSHAKE): called at the start of every
 * input that performs a handshake. */
void fuzz_rng_reset(void);

/* ---- fixtures ------------------------------------------------------------- */

#define FUZZ_ID_A_LEN 5u
#define FUZZ_ID_B_LEN 3u
extern const uint8_t FUZZ_ID_A[FUZZ_ID_A_LEN]; /* "alice" */
extern const uint8_t FUZZ_ID_B[FUZZ_ID_B_LEN]; /* "bob" */

typedef struct {
    mldsa_keypair_t kp_a; /* regenerable from FUZZ_STREAM_IDENTITY_A */
    mldsa_keypair_t kp_b; /* regenerable from FUZZ_STREAM_IDENTITY_B */
    keystore_t ks_responder; /* alice -> A (what bob pins) */
    keystore_t ks_initiator; /* bob -> B (what alice pins) */
} fuzz_identities_t;

const fuzz_identities_t *fuzz_identities(void);

/* Regenerates identity A from its stream into *kp (caller frees with
 * mldsa_keypair_free). Used by fuzz_keys to rebuild its template at runtime. */
void fuzz_regenerate_identity_a(mldsa_keypair_t *kp);

/* The canonical deterministic handshake, run once (after fuzz_rng_reset):
 *   1. initiator (alice -> bob) creates ClientHello
 *   2. responder (bob) accepts it and creates ServerHello
 *   3. initiator verifies ServerHello and creates ClientAuth
 *   4. responder verifies ClientAuth; both finish
 * Harnesses that replay steps 1-2 after fuzz_rng_reset() reproduce ch/sh
 * byte for byte. */
typedef struct {
    uint8_t ch[CLIENT_HELLO_MAX_ENCODED_LEN];
    size_t ch_len;
    uint8_t sh[SERVER_HELLO_MAX_ENCODED_LEN];
    size_t sh_len;
    uint8_t ca[CLIENT_AUTH_MAX_ENCODED_LEN];
    size_t ca_len;
    uint8_t handshake_id[WIRE_HANDSHAKE_ID_LEN];
    uint8_t c2s[KEX_SESSION_KEY_BYTES];
    uint8_t s2c[KEX_SESSION_KEY_BYTES];
} fuzz_transcript_t;

const fuzz_transcript_t *fuzz_genuine_transcript(void);

/* Fixed fake clock for pending stores and sessions. */
extern uint64_t fuzz_clock_now;
uint64_t fuzz_clock_fn(void *ctx);
#define FUZZ_CLOCK_T0 UINT64_C(1000)

/* ---- chunked inputs ----------------------------------------------------------- */

/* Splits a payload into chunks, each preceded by a big-endian length of
 * `prefix_bytes` (2 or 4) clipped to what remains, up to max_chunks. A
 * zero-length payload yields exactly one empty chunk. Chunks never point
 * outside the payload; an empty chunk points at fuzz_empty. */
typedef struct {
    const uint8_t *p;
    size_t n;
    size_t off;
    unsigned count;
    unsigned max_chunks;
    unsigned prefix_bytes;
} fuzz_chunks_t;

void fuzz_chunks_init(fuzz_chunks_t *c, const uint8_t *p, size_t n, unsigned prefix_bytes, unsigned max_chunks);
bool fuzz_chunks_next(fuzz_chunks_t *c, const uint8_t **chunk, size_t *len);

/* Appends a chunk (with its length prefix) to a seed buffer; returns the new length. */
size_t fuzz_seed_put_chunk(uint8_t *seed, size_t seed_len, size_t cap, unsigned prefix_bytes, const uint8_t *chunk,
                           size_t len);

/* ---- per-target interface (implemented by each fuzz_<t>.c) ------------------ */

typedef void (*fuzz_emit_fn)(void *ctx, const char *name, const uint8_t *data, size_t len);

extern const char *const fuzz_target_name;
extern const size_t fuzz_target_max_len;

/* Emits the target's seed corpus (always including the empty input). */
void fuzz_target_seeds(fuzz_emit_fn emit, void *ctx);

/* Extra replay-driver commands (argv[1] onwards). Returns -1 if unhandled,
 * otherwise a process exit status. */
int fuzz_target_command(int argc, char **argv);

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#endif /* MLDSA_AUTH_FUZZ_COMMON_H */
