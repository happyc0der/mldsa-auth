#include "authd_cli.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>

#include "authd_config.h"
#include "authd_secret.h"
#include "authmsg.h"
#include "demo_app.h"
#include "demo_keys.h"
#include "frame.h"
#include "handshake.h"
#include "keyfile.h"
#include "keystore.h"
#include "localapi.h"   /* AUTHD_LIST_MAX */
#include "localcli.h"
#include "mldsa_wrap.h"
#include "net_io.h"
#include "secure_mem.h"
#include "session.h"
#include "store.h"

/* Exit statuses, spec 13. */
#define EX_OK      0
#define EX_FAIL    1
#define EX_USAGE   2
#define EX_CONFIG  3

/* Argon2id parameters by role, spec 12. Named, because a literal 4 next to a
 * literal 3 in two different functions is how they drift apart. */
#define KDF_OPS_SERVER    4u
#define KDF_OPS_OPERATOR  3u
#define KDF_MEM_256MIB    (256u * 1024u * 1024u)

#define LOCAL_TIMEOUT_MS  10000u
#define LOGIN_TIMEOUT_MS  20000u

/* Spec 16 fixes these names whatever the server's id happens to be. */
#define SERVER_KEY_NAME  "server.ek"
#define SERVER_PUB_NAME  "server.pub"
#define STORE_NAME       "store.sqlite3"

/* ---- small shared helpers ----------------------------------------------- */

static int join(char *out, size_t cap, const char *dir, const char *name)
{
    const int n = snprintf(out, cap, "%s/%s", dir, name);
    return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

static int path_exists(const char *path)
{
    struct stat st;
    return lstat(path, &st) == 0;
}

/* One place that says "this option needs a value and did not get one", so the
 * message is identical for every subcommand of both binaries. */
static int unexpected(const char *prog, const char *sub, const char *arg)
{
    fprintf(stderr, "%s %s: unexpected argument '%s'\n", prog, sub, arg);
    return EX_USAGE;
}

static int need(const char *prog, const char *sub, const char *usage)
{
    fprintf(stderr, "usage: %s %s %s\n", prog, sub, usage);
    return EX_USAGE;
}

static int failed(const char *prog, const char *sub, const char *what, const char *status)
{
    fprintf(stderr, "%s %s: failed: %s: %s\n", prog, sub, what, status);
    return EX_FAIL;
}

/* Hex for the line protocol. `out` must hold 2*len+1 bytes. */
static void hexify(char *out, const void *p, size_t len)
{
    (void)sodium_bin2hex(out, 2u * len + 1u, (const unsigned char *)p, len);
}

/* Reads a passphrase file, printing the reason on failure. Configuration
 * problems -- a missing or badly-permissioned passphrase file IS one -- exit
 * 3, not 1. */
static int read_pass(const char *prog, const char *sub, const char *path,
                     uint8_t **out, size_t *out_len)
{
    const authd_secret_status_t st = authd_secret_read(path, out, out_len);
    if (st != AUTHD_SECRET_OK) {
        fprintf(stderr, "%s %s: passphrase file %s: %s\n", prog, sub, path,
                authd_secret_status_name(st));
        return EX_CONFIG;
    }
    return EX_OK;
}

/* Generates a keypair, seals it as MLDSAEK1 at `ek_path`, and publishes the
 * public half at `pub_path`. The MLDSASK2 image exists ONLY in secure memory:
 * spec Req 10 says no plaintext secret key is written to disk by any daemon or
 * CLI command, which is precisely why demo_keys_generate_files() -- which
 * writes one -- cannot be reused here.
 *
 * `pk_out`, when non-NULL, receives the public key. */
static int seal_new_identity(const char *prog, const char *sub, const char *ek_path,
                             const char *pub_path, const uint8_t *id, size_t id_len,
                             const char *pass, size_t pass_len, uint32_t ops, uint64_t mem,
                             uint8_t *pk_out)
{
    mldsa_keypair_t kp;
    memset(&kp, 0, sizeof kp);
    if (mldsa_keypair_generate(&kp) != 0) {
        return failed(prog, sub, ek_path, "keypair-generation-failed");
    }
    const size_t img_len = demo_keys_sk2_image_len(id_len);
    uint8_t *img = (img_len > 0u) ? secure_mem_alloc(img_len) : NULL;
    int rc = EX_FAIL;
    if (img == NULL) {
        (void)failed(prog, sub, ek_path, "allocation-failed");
        goto out;
    }
    const demo_keys_status_t bs = demo_keys_build_sk2_image(img, img_len, id, id_len, &kp);
    if (bs != DEMO_KEYS_OK) {
        (void)failed(prog, sub, ek_path, demo_keys_status_name(bs));
        goto out;
    }
    const keyfile_status_t ks = keyfile_seal(ek_path, img, img_len, pass, pass_len, ops, mem);
    if (ks != KEYFILE_OK) {
        (void)failed(prog, sub, ek_path, keyfile_status_name(ks));
        goto out;
    }
    const demo_keys_status_t ps = demo_keys_write_public(pub_path, id, id_len, kp.public_key);
    if (ps != DEMO_KEYS_OK) {
        (void)failed(prog, sub, pub_path, demo_keys_status_name(ps));
        goto out;
    }
    if (pk_out != NULL) {
        memcpy(pk_out, kp.public_key, MLDSA_PUBLIC_KEY_BYTES);
    }
    rc = EX_OK;
out:
    if (img != NULL) {
        secure_mem_free(img, img_len);
    }
    mldsa_keypair_free(&kp);
    return rc;
}

/* ---- authd_admin: offline subcommands ----------------------------------- */

/* Writes `len` bytes to a new 0600 file, refusing an existing path. */
static int write_secret_file(const char *path, const uint8_t *p, size_t len)
{
    const int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        return -1;
    }
    size_t off = 0;
    int ok = 1;
    while (off < len) {
        const ssize_t n = write(fd, p + off, len - off);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) {
                continue;
            }
            ok = 0;
            break;
        }
        off += (size_t)n;
    }
    ok = ok && fsync(fd) == 0;
    ok = close(fd) == 0 && ok;
    if (!ok) {
        (void)unlink(path);
        return -1;
    }
    return 0;
}

static int cmd_init(int argc, char **argv, const char *prog)
{
    const char *dir = NULL, *id_s = NULL, *pass_path = NULL;
    for (int i = 2; i < argc; i++) {
        const int has = (i + 1 < argc);
        if (strcmp(argv[i], "--dir") == 0 && has)                  { dir = argv[++i]; }
        else if (strcmp(argv[i], "--server-id") == 0 && has)       { id_s = argv[++i]; }
        else if (strcmp(argv[i], "--passphrase-file") == 0 && has) { pass_path = argv[++i]; }
        else { return unexpected(prog, "init", argv[i]); }
    }
    const uint8_t *id = NULL;
    size_t id_len = 0;
    if (dir == NULL || id_s == NULL || pass_path == NULL || demo_parse_id(id_s, &id, &id_len) != 0) {
        return need(prog, "init", "--dir DIR --server-id ID --passphrase-file PATH");
    }

    char ek[PATH_MAX], pub[PATH_MAX], db[PATH_MAX];
    if (join(ek, sizeof ek, dir, SERVER_KEY_NAME) != 0 ||
        join(pub, sizeof pub, dir, SERVER_PUB_NAME) != 0 ||
        join(db, sizeof db, dir, STORE_NAME) != 0) {
        return need(prog, "init", "--dir DIR --server-id ID --passphrase-file PATH");
    }

    /* Refuse if ANY of the three already exists, and name which one.
     *
     * This is not tidiness. store_open() succeeds on an existing store and
     * derives key_audit = HKDF(KEK, store_id, ...); re-running init with a
     * different passphrase would derive it from a DIFFERENT KEK, every
     * subsequent audit row would chain under the wrong key, and
     * store_audit_verify() would fail forever -- with nothing reported at the
     * moment of damage. Refusing up front is the only cheap defence. */
    const char *clash = path_exists(ek) ? ek : (path_exists(db) ? db : (path_exists(pass_path) ? pass_path : NULL));
    if (clash != NULL) {
        fprintf(stderr, "%s init: refusing: %s already exists (init is not resumable; "
                        "remove the whole directory to start over)\n", prog, clash);
        return EX_FAIL;
    }
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        return failed(prog, "init", dir, "cannot-create-directory");
    }

    /* Spec 12: the server passphrase is 32 random bytes, delivered by a
     * systemd credential. It is written FIRST and then read BACK through the
     * same reader the daemon uses, and the key is sealed under what the file
     * actually contains.
     *
     * That ordering is load-bearing. The reader strips one trailing newline,
     * so sealing under the in-memory bytes would produce a key the daemon
     * cannot open whenever the last random byte happens to be 0x0A -- one
     * time in 256, reported as success, discovered much later. Reading back
     * is also what makes this command's second Argon2id worth its cost: it
     * verifies the file-to-key binding rather than re-deriving a known
     * answer. */
    uint8_t seed[32];
    randombytes_buf(seed, sizeof seed);
    const int wrote = write_secret_file(pass_path, seed, sizeof seed);
    sodium_memzero(seed, sizeof seed);
    if (wrote != 0) {
        return failed(prog, "init", pass_path, "cannot-write-passphrase-file");
    }

    uint8_t *pass = NULL;
    size_t pass_len = 0;
    int rc = read_pass(prog, "init", pass_path, &pass, &pass_len);
    if (rc != EX_OK) {
        return rc;
    }

    rc = seal_new_identity(prog, "init", ek, pub, id, id_len, (const char *)pass, pass_len,
                           KDF_OPS_SERVER, KDF_MEM_256MIB, NULL);
    if (rc != EX_OK) {
        authd_secret_free(pass, pass_len);
        fprintf(stderr, "%s init: nothing was created beyond %s; remove it before retrying\n",
                prog, pass_path);
        return rc;
    }

    /* Reopen: proves the sealed file opens with the passphrase AS WRITTEN, and
     * yields the KEK the store's audit chain is keyed from (spec 9.2.4). */
    mldsa_keypair_t kp;
    memset(&kp, 0, sizeof kp);
    uint8_t *kek = secure_mem_alloc(STORE_KEK_BYTES);
    if (kek == NULL) {
        authd_secret_free(pass, pass_len);
        return failed(prog, "init", ek, "allocation-failed");
    }
    const keyfile_status_t ks = keyfile_open(ek, id, id_len, (const char *)pass, pass_len, &kp, kek);
    authd_secret_free(pass, pass_len);
    if (ks != KEYFILE_OK) {
        secure_mem_free(kek, STORE_KEK_BYTES);
        return failed(prog, "init", ek, keyfile_status_name(ks));
    }
    mldsa_keypair_free(&kp);   /* init needs the KEK, not the key */

    store_t *store = NULL;
    const store_status_t ss = store_open(db, kek, &store);
    secure_mem_free(kek, STORE_KEK_BYTES);
    if (ss != STORE_OK) {
        fprintf(stderr, "%s init: failed: %s: %s\n", prog, db, store_status_name(ss));
        fprintf(stderr, "%s init: %s and %s exist and must be removed before retrying\n",
                prog, ek, pass_path);
        return EX_FAIL;
    }
    store_close(store);

    /* store_open creates the database with the CALLER'S umask, and this
     * command runs from an operator's interactive shell where that is
     * typically 022 -- which would leave token hashes, the audit chain and
     * every enrolled public key world-readable. SQLite gives -wal and -shm the
     * main file's mode, so fixing this one fixes all three. */
    char aux[PATH_MAX];
    (void)chmod(db, 0600);
    if (snprintf(aux, sizeof aux, "%s-wal", db) > 0) { (void)chmod(aux, 0600); }
    if (snprintf(aux, sizeof aux, "%s-shm", db) > 0) { (void)chmod(aux, 0600); }

    printf("%s init: created %s (mode 0700)\n", prog, dir);
    printf("%s init: %s (MLDSAEK1, ops=%u mem=%llu, mode 0600)\n", prog, ek,
           (unsigned)KDF_OPS_SERVER, (unsigned long long)KDF_MEM_256MIB);
    printf("%s init: %s (MLDSAPK1) -- pin this in every client\n", prog, pub);
    printf("%s init: %s (mode 0600)\n", prog, db);
    printf("%s init: %s holds the passphrase (mode 0600)\n", prog, pass_path);
    fprintf(stderr, "NOTE: move %s into a systemd credential (systemd-creds encrypt) and\n"
                    "delete the plaintext copy. Losing it makes %s and %s unrecoverable:\n"
                    "there is no escrow and no recovery path.\n", pass_path, ek, db);
    return EX_OK;
}

static int cmd_keygen_server(int argc, char **argv, const char *prog)
{
    const char *key = NULL, *pub = NULL, *id_s = NULL, *pass_path = NULL;
    for (int i = 2; i < argc; i++) {
        const int has = (i + 1 < argc);
        if (strcmp(argv[i], "--key") == 0 && has)                  { key = argv[++i]; }
        else if (strcmp(argv[i], "--pub") == 0 && has)             { pub = argv[++i]; }
        else if (strcmp(argv[i], "--server-id") == 0 && has)       { id_s = argv[++i]; }
        else if (strcmp(argv[i], "--passphrase-file") == 0 && has) { pass_path = argv[++i]; }
        else { return unexpected(prog, "keygen-server", argv[i]); }
    }
    const uint8_t *id = NULL;
    size_t id_len = 0;
    if (key == NULL || pub == NULL || id_s == NULL || pass_path == NULL ||
        demo_parse_id(id_s, &id, &id_len) != 0) {
        return need(prog, "keygen-server", "--key PATH --pub PATH --server-id ID --passphrase-file PATH");
    }
    uint8_t *pass = NULL;
    size_t pass_len = 0;
    int rc = read_pass(prog, "keygen-server", pass_path, &pass, &pass_len);
    if (rc != EX_OK) {
        return rc;
    }
    rc = seal_new_identity(prog, "keygen-server", key, pub, id, id_len, (const char *)pass, pass_len,
                           KDF_OPS_SERVER, KDF_MEM_256MIB, NULL);
    authd_secret_free(pass, pass_len);
    if (rc == EX_OK) {
        printf("%s keygen-server: wrote %s (MLDSAEK1, mode 0600) and %s\n", prog, key, pub);
    }
    return rc;
}

static int cmd_migrate_key(int argc, char **argv, const char *prog)
{
    const char *in = NULL, *out = NULL, *id_s = NULL, *pass_path = NULL;
    for (int i = 2; i < argc; i++) {
        const int has = (i + 1 < argc);
        if (strcmp(argv[i], "--in") == 0 && has)                   { in = argv[++i]; }
        else if (strcmp(argv[i], "--out") == 0 && has)             { out = argv[++i]; }
        else if (strcmp(argv[i], "--id") == 0 && has)              { id_s = argv[++i]; }
        else if (strcmp(argv[i], "--passphrase-file") == 0 && has) { pass_path = argv[++i]; }
        else { return unexpected(prog, "migrate-key", argv[i]); }
    }
    const uint8_t *id = NULL;
    size_t id_len = 0;
    if (in == NULL || out == NULL || id_s == NULL || pass_path == NULL ||
        demo_parse_id(id_s, &id, &id_len) != 0) {
        return need(prog, "migrate-key", "--id ID --in OLD.sk --out NEW.ek --passphrase-file PATH");
    }
    uint8_t *pass = NULL;
    size_t pass_len = 0;
    int rc = read_pass(prog, "migrate-key", pass_path, &pass, &pass_len);
    if (rc != EX_OK) {
        return rc;
    }
    mldsa_keypair_t kp;
    memset(&kp, 0, sizeof kp);
    const demo_keys_status_t ls = demo_keys_load_identity(in, id, id_len, &kp);
    if (ls != DEMO_KEYS_OK) {
        authd_secret_free(pass, pass_len);
        return failed(prog, "migrate-key", in, demo_keys_status_name(ls));
    }
    const size_t img_len = demo_keys_sk2_image_len(id_len);
    uint8_t *img = (img_len > 0u) ? secure_mem_alloc(img_len) : NULL;
    rc = EX_FAIL;
    if (img == NULL) {
        (void)failed(prog, "migrate-key", out, "allocation-failed");
        goto done;
    }
    if (demo_keys_build_sk2_image(img, img_len, id, id_len, &kp) != DEMO_KEYS_OK) {
        (void)failed(prog, "migrate-key", out, "image-build-failed");
        goto done;
    }
    {
        const keyfile_status_t ks = keyfile_seal(out, img, img_len, (const char *)pass, pass_len,
                                                 KDF_OPS_SERVER, KDF_MEM_256MIB);
        if (ks != KEYFILE_OK) {
            (void)failed(prog, "migrate-key", out, keyfile_status_name(ks));
            goto done;
        }
    }
    rc = EX_OK;
    /* Spec 12, printed on EVERY success: the source is still there, in the
     * clear, and this command cannot destroy it safely on the operator's
     * behalf -- it does not know what else references it. */
    fprintf(stderr, "WARNING: %s is UNENCRYPTED and was NOT modified. Destroy the plaintext\n"
                    "once %s has been verified -- until then the secret key exists twice,\n"
                    "and the weaker copy is the one that decides your security.\n", in, out);
    printf("%s migrate-key: wrote %s (MLDSAEK1, mode 0600)\n", prog, out);
done:
    if (img != NULL) {
        secure_mem_free(img, img_len);
    }
    mldsa_keypair_free(&kp);
    authd_secret_free(pass, pass_len);
    return rc;
}

static int cmd_rewrap(int argc, char **argv, const char *prog)
{
    const char *in = NULL, *out = NULL, *id_s = NULL, *oldp = NULL, *newp = NULL;
    for (int i = 2; i < argc; i++) {
        const int has = (i + 1 < argc);
        if (strcmp(argv[i], "--in") == 0 && has)                       { in = argv[++i]; }
        else if (strcmp(argv[i], "--out") == 0 && has)                 { out = argv[++i]; }
        else if (strcmp(argv[i], "--id") == 0 && has)                  { id_s = argv[++i]; }
        else if (strcmp(argv[i], "--old-passphrase-file") == 0 && has) { oldp = argv[++i]; }
        else if (strcmp(argv[i], "--new-passphrase-file") == 0 && has) { newp = argv[++i]; }
        else { return unexpected(prog, "rewrap", argv[i]); }
    }
    const uint8_t *id = NULL;
    size_t id_len = 0;
    if (in == NULL || out == NULL || id_s == NULL || oldp == NULL || newp == NULL ||
        demo_parse_id(id_s, &id, &id_len) != 0) {
        return need(prog, "rewrap",
                    "--id ID --in OLD.ek --out NEW.ek --old-passphrase-file A --new-passphrase-file B");
    }
    uint8_t *pa = NULL, *pb = NULL;
    size_t la = 0, lb = 0;
    int rc = read_pass(prog, "rewrap", oldp, &pa, &la);
    if (rc != EX_OK) {
        return rc;
    }
    rc = read_pass(prog, "rewrap", newp, &pb, &lb);
    if (rc != EX_OK) {
        authd_secret_free(pa, la);
        return rc;
    }
    mldsa_keypair_t kp;
    memset(&kp, 0, sizeof kp);
    uint8_t *img = NULL;
    size_t img_len = 0;
    const keyfile_status_t ko = keyfile_open(in, id, id_len, (const char *)pa, la, &kp, NULL);
    if (ko != KEYFILE_OK) {
        rc = failed(prog, "rewrap", in, keyfile_status_name(ko));
        goto done;
    }
    img_len = demo_keys_sk2_image_len(id_len);
    img = (img_len > 0u) ? secure_mem_alloc(img_len) : NULL;
    if (img == NULL || demo_keys_build_sk2_image(img, img_len, id, id_len, &kp) != DEMO_KEYS_OK) {
        rc = failed(prog, "rewrap", out, "image-build-failed");
        goto done;
    }
    {
        /* keyfile_seal publishes with O_EXCL + link(), so --out equal to --in
         * is EXISTS rather than a half-written key. Never in place: an
         * interrupted rewrap must leave the OLD file openable. */
        const keyfile_status_t ks = keyfile_seal(out, img, img_len, (const char *)pb, lb,
                                                 KDF_OPS_SERVER, KDF_MEM_256MIB);
        if (ks != KEYFILE_OK) {
            rc = failed(prog, "rewrap", out, keyfile_status_name(ks));
            goto done;
        }
    }
    rc = EX_OK;
    printf("%s rewrap: wrote %s (MLDSAEK1, mode 0600); %s was not modified\n", prog, out, in);
done:
    if (img != NULL) {
        secure_mem_free(img, img_len);
    }
    mldsa_keypair_free(&kp);
    authd_secret_free(pa, la);
    authd_secret_free(pb, lb);
    return rc;
}

/* ---- authd_admin: online subcommands (clients of admin.sock) ------------ */

/* Sends one request and reports it.
 *
 * The response is printed VERBATIM, and that is a decision rather than
 * laziness: identifiers and labels are hex on the wire, and spec 3.2 calls
 * them attacker-influenced strings that must be escaped anywhere they are
 * displayed. Printing the hex means this tool has no display decoder to get
 * wrong and no terminal-escape hazard at all. `xxd -r -p` decodes one value
 * when an operator wants it.
 *
 * LOCALCLI_OK means a well-formed response arrived, not that the daemon
 * agreed: a refusal is exit 1 with the ERR code named. */
static int local_call(const char *prog, const char *sub, const char *sock,
                      const char *cmd, const char *args)
{
    static char resp[LOCALCLI_RESP_MAX + 1u];
    size_t len = 0;
    const localcli_status_t st = localcli_call(sock, cmd, args, LOCAL_TIMEOUT_MS,
                                               resp, sizeof resp, &len);
    if (st != LOCALCLI_OK) {
        fprintf(stderr, "%s %s: %s: %s\n", prog, sub, sock, localcli_status_name(st));
        return EX_FAIL;
    }
    char code[64];
    if (localcli_error_code(resp, code, sizeof code)) {
        fprintf(stderr, "%s %s: refused: %s\n", prog, sub, code);
        return EX_FAIL;
    }
    (void)fwrite(resp, 1u, len, stdout);
    return EX_OK;
}

/* Every online subcommand shares one option loop: --socket plus up to four
 * declared keys. Each key is either sent as hex (an identifier, a label, a
 * reason, a path) or verbatim (a decimal count). */
typedef struct {
    const char *flag;   /* "--user" */
    const char *key;    /* "user" */
    int         hex;    /* 1 = hex-encode the value */
    int         required;
    const char *val;
} opt_t;

static int online(int argc, char **argv, const char *prog, const char *sub,
                  const char *cmd, opt_t *opts, size_t n_opts, const char *usage)
{
    const char *sock = NULL;
    for (int i = 2; i < argc; i++) {
        const int has = (i + 1 < argc);
        if (strcmp(argv[i], "--socket") == 0 && has) {
            sock = argv[++i];
            continue;
        }
        size_t k = 0;
        for (; k < n_opts; k++) {
            if (strcmp(argv[i], opts[k].flag) == 0 && has) {
                opts[k].val = argv[++i];
                break;
            }
        }
        if (k == n_opts) {
            return unexpected(prog, sub, argv[i]);
        }
    }
    if (sock == NULL) {
        return need(prog, sub, usage);
    }
    for (size_t k = 0; k < n_opts; k++) {
        if (opts[k].required && opts[k].val == NULL) {
            return need(prog, sub, usage);
        }
    }

    char args[AUTHD_LINE_MAX];
    size_t off = 0;
    for (size_t k = 0; k < n_opts; k++) {
        if (opts[k].val == NULL) {
            continue;
        }
        const size_t vlen = strlen(opts[k].val);
        /* 2*vlen for hex, plus " key=" and a NUL. Refused here rather than
         * truncated: a silently shortened identifier would name a different
         * device. */
        if (off + strlen(opts[k].key) + 2u * vlen + 3u >= sizeof args) {
            fprintf(stderr, "%s %s: %s is too long\n", prog, sub, opts[k].flag);
            return EX_USAGE;
        }
        const int n = snprintf(args + off, sizeof args - off, "%s%s=", (off > 0u) ? " " : "",
                               opts[k].key);
        if (n < 0) {
            return EX_USAGE;
        }
        off += (size_t)n;
        if (opts[k].hex) {
            hexify(args + off, opts[k].val, vlen);
            off += 2u * vlen;
        } else {
            const int m = snprintf(args + off, sizeof args - off, "%s", opts[k].val);
            if (m < 0) {
                return EX_USAGE;
            }
            off += (size_t)m;
        }
    }
    args[off] = '\0';
    return local_call(prog, sub, sock, cmd, args);
}

static int cmd_enroll_operator(int argc, char **argv, const char *prog)
{
    const char *sock = NULL, *user = NULL, *handle = NULL, *pubpath = NULL, *label = NULL;
    for (int i = 2; i < argc; i++) {
        const int has = (i + 1 < argc);
        if (strcmp(argv[i], "--socket") == 0 && has)      { sock = argv[++i]; }
        else if (strcmp(argv[i], "--user") == 0 && has)   { user = argv[++i]; }
        else if (strcmp(argv[i], "--handle") == 0 && has) { handle = argv[++i]; }
        else if (strcmp(argv[i], "--pub") == 0 && has)    { pubpath = argv[++i]; }
        else if (strcmp(argv[i], "--label") == 0 && has)  { label = argv[++i]; }
        else { return unexpected(prog, "enroll-operator", argv[i]); }
    }
    if (sock == NULL || user == NULL || handle == NULL || pubpath == NULL) {
        return need(prog, "enroll-operator",
                    "--socket PATH --user ID --handle H --pub H.pub [--label TEXT]");
    }
    const uint8_t *hid = NULL;
    size_t hid_len = 0;
    if (demo_parse_id(handle, &hid, &hid_len) != 0) {
        return need(prog, "enroll-operator", "--handle must be 1-64 of [A-Za-z0-9._-]");
    }
    /* The handle on the command line is the authority, and the file must AGREE
     * with it: demo_keys_load_public compares the id embedded in the MLDSAPK1
     * file against it and returns ID_MISMATCH otherwise.
     *
     * This is the V2-9 rule -- migration must not be the one path that trusts
     * a file's own label -- applied to enrollment. Taking the handle from the
     * file would mean a renamed or swapped .pub silently enrolls a different
     * device under the operator's user. */
    uint8_t pk[MLDSA_PUBLIC_KEY_BYTES];
    const demo_keys_status_t ps = demo_keys_load_public(pubpath, hid, hid_len, pk);
    if (ps != DEMO_KEYS_OK) {
        return failed(prog, "enroll-operator", pubpath, demo_keys_status_name(ps));
    }
    char *pk_hex = (char *)malloc(2u * sizeof pk + 1u);
    if (pk_hex == NULL) {
        return failed(prog, "enroll-operator", pubpath, "allocation-failed");
    }
    hexify(pk_hex, pk, sizeof pk);

    char args[AUTHD_LINE_MAX];
    char user_hex[2u * 64u + 1u], handle_hex[2u * 64u + 1u], label_hex[2u * 64u + 1u];
    if (strlen(user) > 64u || strlen(handle) > 64u || (label != NULL && strlen(label) > 64u)) {
        free(pk_hex);
        fprintf(stderr, "%s enroll-operator: user, handle and label are at most 64 bytes\n", prog);
        return EX_USAGE;
    }
    hexify(user_hex, user, strlen(user));
    hexify(handle_hex, handle, strlen(handle));
    hexify(label_hex, (label != NULL) ? label : "", (label != NULL) ? strlen(label) : 0u);
    const int n = snprintf(args, sizeof args, "user=%s handle=%s pk=%s label=%s via=site",
                           user_hex, handle_hex, pk_hex, label_hex);
    free(pk_hex);
    if (n < 0 || (size_t)n >= sizeof args) {
        return failed(prog, "enroll-operator", pubpath, "request-too-long");
    }
    return local_call(prog, "enroll-operator", sock, "ENROLL-OPERATOR", args);
}

static int cmd_backup(int argc, char **argv, const char *prog)
{
    const char *sock = NULL, *path = NULL;
    for (int i = 2; i < argc; i++) {
        const int has = (i + 1 < argc);
        if (strcmp(argv[i], "--socket") == 0 && has)    { sock = argv[++i]; }
        else if (strcmp(argv[i], "--path") == 0 && has) { path = argv[++i]; }
        else { return unexpected(prog, "backup", argv[i]); }
    }
    if (sock == NULL || path == NULL) {
        return need(prog, "backup", "--socket PATH --path /absolute/destination");
    }
    /* VACUUM INTO runs inside the DAEMON, so a relative path resolves against
     * the daemon's working directory, not this shell's. Refusing one here is
     * the difference between a backup the operator can find and a file that
     * appears somewhere under the service's root. */
    if (path[0] != '/') {
        fprintf(stderr, "%s backup: --path must be absolute: the daemon resolves it, "
                        "not this shell\n", prog);
        return EX_USAGE;
    }
    char args[AUTHD_LINE_MAX];
    const size_t plen = strlen(path);
    if (2u * plen + 8u >= sizeof args) {
        return failed(prog, "backup", path, "request-too-long");
    }
    memcpy(args, "path=", 5u);
    hexify(args + 5u, path, plen);
    return local_call(prog, "backup", sock, "BACKUP", args);
}

/* ---- authd_admin: --check-config ---------------------------------------- */

/* Delegates to the SAME authd_config_load() and authd_config_check_paths()
 * the daemon calls. Not a second validator: two validators drift, and the one
 * an operator runs would then approve a config the one that matters rejects. */
static int cmd_check_config(int argc, char **argv, const char *prog)
{
    const char *path = NULL;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            path = argv[++i];
        } else {
            return unexpected(prog, "--check-config", argv[i]);
        }
    }
    if (path == NULL) {
        return need(prog, "--check-config", "--config PATH");
    }
    authd_config_t cfg;
    size_t err_line = 0;
    const authd_config_status_t cs = authd_config_load(path, &cfg, &err_line);
    if (cs != AUTHD_CFG_OK) {
        fprintf(stderr, "%s: %s: %s", prog, path, authd_config_status_name(cs));
        if (err_line > 0u) {
            fprintf(stderr, " at line %zu", err_line);
        }
        fprintf(stderr, "\n");
        return EX_CONFIG;
    }
    char detail[AUTHD_CONFIG_DETAIL_MAX];
    const authd_config_status_t ps = authd_config_check_paths(&cfg, detail, sizeof detail);
    if (ps != AUTHD_CFG_OK) {
        fprintf(stderr, "%s: %s: %s\n", prog, path, detail);
        return EX_CONFIG;
    }
    printf("%s: %s is valid (max_slots=%u handshake_timeout_ms=%u idle_timeout_ms=%u "
           "pad_bucket=%u)\n", prog, path, cfg.max_slots, cfg.handshake_timeout_ms,
           cfg.idle_timeout_ms, cfg.pad_bucket);
    return EX_OK;
}

/* ---- authd_admin dispatch ------------------------------------------------ */

static void admin_usage(const char *prog)
{
    fprintf(stderr,
            "usage:\n"
            "  %s init            --dir DIR --server-id ID --passphrase-file PATH\n"
            "  %s keygen-server   --key PATH --pub PATH --server-id ID --passphrase-file PATH\n"
            "  %s migrate-key     --id ID --in OLD.sk --out NEW.ek --passphrase-file PATH\n"
            "  %s rewrap          --id ID --in OLD.ek --out NEW.ek\n"
            "                     --old-passphrase-file A --new-passphrase-file B\n"
            "  %s enroll-operator --socket S --user ID --handle H --pub H.pub [--label TEXT]\n"
            "  %s disable-user    --socket S --user ID --reason TEXT\n"
            "  %s enable-user     --socket S --user ID\n"
            "  %s list-users      --socket S\n"
            "  %s list-devices    --socket S --user ID\n"
            "  %s audit-tail      --socket S --n N        (1..24)\n"
            "  %s backup          --socket S --path /absolute/destination\n"
            "  %s --check-config  --config PATH\n"
            "\n"
            "Passphrases are FILES (mode 0600, owned by you). There is no prompt and no\n"
            "environment variable: argv and the environment are readable by other processes.\n"
            "Exit: 0 ok, 1 operation failed, 2 usage, 3 configuration.\n",
            prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog);
}

int authd_cli_admin(int argc, char **argv)
{
    const char *prog = (argc > 0 && argv[0] != NULL) ? argv[0] : "authd_admin";
    if (argc < 2) {
        admin_usage(prog);
        return EX_USAGE;
    }
    const char *sub = argv[1];

    if (strcmp(sub, "init") == 0)           { return cmd_init(argc, argv, prog); }
    if (strcmp(sub, "keygen-server") == 0)  { return cmd_keygen_server(argc, argv, prog); }
    if (strcmp(sub, "migrate-key") == 0)    { return cmd_migrate_key(argc, argv, prog); }
    if (strcmp(sub, "rewrap") == 0)         { return cmd_rewrap(argc, argv, prog); }
    if (strcmp(sub, "enroll-operator") == 0){ return cmd_enroll_operator(argc, argv, prog); }
    if (strcmp(sub, "backup") == 0)         { return cmd_backup(argc, argv, prog); }
    if (strcmp(sub, "--check-config") == 0) { return cmd_check_config(argc, argv, prog); }

    if (strcmp(sub, "disable-user") == 0) {
        opt_t o[] = { { "--user", "user", 1, 1, NULL }, { "--reason", "reason", 1, 1, NULL } };
        return online(argc, argv, prog, sub, "DISABLE-USER", o, 2,
                      "--socket PATH --user ID --reason TEXT");
    }
    if (strcmp(sub, "enable-user") == 0) {
        opt_t o[] = { { "--user", "user", 1, 1, NULL } };
        return online(argc, argv, prog, sub, "ENABLE-USER", o, 1, "--socket PATH --user ID");
    }
    if (strcmp(sub, "list-users") == 0) {
        return online(argc, argv, prog, sub, "LIST-USERS", NULL, 0, "--socket PATH");
    }
    if (strcmp(sub, "list-devices") == 0) {
        opt_t o[] = { { "--user", "user", 1, 1, NULL } };
        return online(argc, argv, prog, sub, "LIST-DEVICES", o, 1, "--socket PATH --user ID");
    }
    if (strcmp(sub, "audit-tail") == 0) {
        /* n is DECIMAL on the wire, not hex (localapi's h_audit_tail), and the
         * daemon caps it at AUTHD_LIST_MAX. Refusing a larger value here names
         * the bound; sending it would come back as an unexplained
         * `malformed`. */
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--n") == 0 && i + 1 < argc) {
                uint64_t v = 0;
                if (demo_parse_u64(argv[i + 1], 1u, AUTHD_LIST_MAX, &v) != 0) {
                    fprintf(stderr, "%s audit-tail: --n must be 1..%u\n", prog,
                            (unsigned)AUTHD_LIST_MAX);
                    return EX_USAGE;
                }
            }
        }
        opt_t o[] = { { "--n", "n", 0, 1, NULL } };
        return online(argc, argv, prog, sub, "AUDIT-TAIL", o, 1, "--socket PATH --n 1..24");
    }

    fprintf(stderr, "%s: unknown subcommand '%s'\n", prog, sub);
    admin_usage(prog);
    return EX_USAGE;
}

/* ---- authd_client -------------------------------------------------------- */

/* The library exports no handshake_status_name(); spec 13 requires a failure to
 * print a name from the same enum the daemon logs, not an integer an operator
 * would have to look up. */
static const char *hs_name(handshake_status_t st)
{
    switch (st) {
    case HANDSHAKE_OK:                        return "ok";
    case HANDSHAKE_ERR_INVALID_ARG:           return "invalid-argument";
    case HANDSHAKE_ERR_UNEXPECTED_STATE:      return "unexpected-state";
    case HANDSHAKE_ERR_MALFORMED:             return "malformed";
    case HANDSHAKE_ERR_UNKNOWN_IDENTITY:      return "unknown-identity";
    case HANDSHAKE_ERR_IDENTITY_KEY_MISMATCH: return "identity-key-mismatch";
    case HANDSHAKE_ERR_PEER_IDENTITY_MISMATCH:return "peer-identity-mismatch";
    case HANDSHAKE_ERR_SESSION_ID_MISMATCH:   return "session-id-mismatch";
    case HANDSHAKE_ERR_HANDSHAKE_ID_MISMATCH: return "handshake-id-mismatch";
    case HANDSHAKE_ERR_REPLAY:                return "replay";
    case HANDSHAKE_ERR_EXPIRED:               return "expired";
    case HANDSHAKE_ERR_SIGNATURE:             return "signature";
    case HANDSHAKE_ERR_AUTH_FAILURE_LIMIT:    return "auth-failure-limit";
    case HANDSHAKE_ERR_KEX:                   return "kex";
    case HANDSHAKE_ERR_RESOURCE_EXHAUSTED:    return "resource-exhausted";
    case HANDSHAKE_ERR_INTERNAL:              return "internal";
    }
    return "unknown";
}

/* ---- one authenticated session, shared by login and rotate --------------- */

typedef struct {
    net_conn_t  conn;
    session_t   sess;
    keystore_t  pins;
    uint64_t    deadline;
    uint8_t     hsid[AUTHMSG_HANDSHAKE_ID_BYTES];
    authmsg_login_code_t code;
    int         live;
    /* The proxy-facing Unix socket speaks WebSocket (spec §7.1); the loopback
     * port an operator tunnels to speaks the frame stream raw. Which one this
     * is decides how a frame is put on the wire, and nothing else -- the
     * handshake, the session and every message above are identical. */
    int         ws;
} client_session_t;

/* ---- the WebSocket carrier, client side -------------------------------- */

/* Completes the RFC 6455 opening handshake. The accept value is CHECKED: a
 * client that skipped it would happily "upgrade" with something that never
 * read its key. */
static int ws_do_upgrade(client_session_t *cs, const char *state)
{
    uint8_t nonce[16];
    randombytes_buf(nonce, sizeof nonce);

    char req[512];
    size_t req_len = 0;
    char expect[WS_ACCEPT_B64_LEN + 1u];
    if (ws_client_request(req, sizeof req, &req_len, "/authd/v1", state, nonce, expect) != 0) {
        return -1;
    }
    if (net_write_all(&cs->conn, (const uint8_t *)req, req_len, cs->deadline) != NET_OK) {
        return -1;
    }

    /* The response header block is small and bounded; reading it a byte at a
     * time keeps this to one primitive (net_read_exact) and cannot over-read
     * into the first WebSocket frame. */
    uint8_t resp[1024];
    size_t n = 0;
    while (n < sizeof resp) {
        size_t got = 0;
        if (net_read_exact(&cs->conn, resp + n, 1u, cs->deadline, &got) != NET_OK) {
            return -1;
        }
        n++;
        if (n >= 4u && memcmp(resp + n - 4u, "\r\n\r\n", 4) == 0) {
            break;
        }
    }
    return ws_client_check_101(resp, n, expect);
}

/* The shared reader in ws.c, over this session's socket. */
static int cs_read_exact(void *ctx, uint8_t *buf, size_t n)
{
    client_session_t *cs = (client_session_t *)ctx;
    size_t got = 0;
    const net_status_t ns = net_read_exact(&cs->conn, buf, n, cs->deadline, &got);
    if (ns == NET_OK)  { return 0; }
    if (ns == NET_EOF && got == 0u) { return 1; }   /* clean EOF at a boundary */
    return -1;
}

/* frame_send/frame_recv, or the same thing inside a WebSocket message. The
 * callers below are identical either way, which is the point. */
static frame_status_t cs_send(client_session_t *cs, uint8_t *buf, size_t payload_len)
{
    if (!cs->ws) {
        return cs_send(cs, buf, payload_len);
    }
    frame_put_header(buf, (uint32_t)payload_len);
    static uint8_t wf[WS_SRV_HDR_MAX + 4u + FRAME_BUF_BYTES];
    uint8_t mask[4];
    randombytes_buf(mask, sizeof mask);
    const size_t n = ws_client_frame(wf, sizeof wf, buf, FRAME_HEADER_BYTES + payload_len, mask);
    if (n == 0u) { return FRAME_INVALID_ARG; }
    const net_status_t ns = net_write_all(&cs->conn, wf, n, cs->deadline);
    sodium_memzero(wf, n);
    return (ns == NET_OK) ? FRAME_OK : FRAME_IO;
}

static frame_status_t cs_recv(client_session_t *cs, uint8_t *buf, size_t min_len, size_t max_len,
                              size_t *payload_len)
{
    if (!cs->ws) {
        return frame_recv(&cs->conn, buf, min_len, max_len, payload_len, cs->deadline);
    }
    *payload_len = 0u;
    size_t msg = 0u;
    const ws_client_status_t ws = ws_client_read_message(cs_read_exact, cs, buf,
                                                         FRAME_HEADER_BYTES + max_len, &msg);
    if (ws == WS_CLIENT_CLOSED)   { return FRAME_EOF; }
    if (ws == WS_CLIENT_IO)       { return FRAME_IO; }
    if (ws != WS_CLIENT_OK)       { return FRAME_BAD_LENGTH; }
    if (msg < FRAME_HEADER_BYTES) { return FRAME_TRUNCATED; }
    const uint32_t plen = frame_get_header(buf);
    if ((size_t)plen != msg - FRAME_HEADER_BYTES || plen < min_len || plen > max_len) {
        return FRAME_BAD_LENGTH;
    }
    /* frame_recv's contract: payload at buf + FRAME_HEADER_BYTES. It already is. */
    *payload_len = plen;
    return FRAME_OK;
}

static void client_session_close(client_session_t *cs)
{
    sodium_memzero(&cs->code, sizeof cs->code);
    sodium_memzero(cs->hsid, sizeof cs->hsid);
    session_wipe(&cs->sess);
    keystore_wipe(&cs->pins);
    net_close(&cs->conn);
    cs->live = 0;
}

/* Handshake, then receive the LOGIN_CODE the daemon sends as its first record.
 * Returns EX_OK with `cs` live, or an exit status with everything wiped.
 *
 * `quiet` suppresses the diagnostics, because rotate PROBES with keys it fully
 * expects to fail -- a probe that printed an error for every attempt would
 * make a normal interrupted-rename recovery look like a fault. */
static int client_open_session(const char *prog, const char *sub, int quiet,
                               const mldsa_keypair_t *kp,
                               const uint8_t *hid, size_t hid_len,
                               const uint8_t *sid, size_t sid_len,
                               const uint8_t *server_pk,
                               const char *unix_path, uint16_t port,
                               const char *state,
                               client_session_t *cs)
{
    memset(cs, 0, sizeof *cs);
    net_conn_init(&cs->conn);
    keystore_init(&cs->pins);
    cs->deadline = net_deadline_in(LOGIN_TIMEOUT_MS);

    if (keystore_add(&cs->pins, sid, sid_len, server_pk) != KEYSTORE_OK) {
        keystore_wipe(&cs->pins);
        return EX_FAIL;
    }
    const net_status_t ns = (unix_path != NULL)
                                ? net_connect_unix(unix_path, cs->deadline, &cs->conn)
                                : net_connect_loopback(port, cs->deadline, &cs->conn);
    if (ns != NET_OK) {
        if (!quiet) {
            fprintf(stderr, "%s %s: cannot connect: %s\n", prog, sub, net_status_name(ns));
        }
        keystore_wipe(&cs->pins);
        return EX_FAIL;
    }

    /* The Unix socket IS the proxy-facing listener, and that one speaks
     * WebSocket (spec §7.1). The loopback port is the operator's tunnel and
     * stays raw. Nothing above this line knows the difference. */
    cs->ws = (unix_path != NULL);
    if (cs->ws && ws_do_upgrade(cs, state) != 0) {
        if (!quiet) {
            fprintf(stderr, "%s %s: WebSocket upgrade failed\n", prog, sub);
        }
        net_close(&cs->conn);
        keystore_wipe(&cs->pins);
        return EX_FAIL;
    }

    static uint8_t tx[FRAME_BUF_BYTES];
    static uint8_t rx[FRAME_BUF_BYTES];
    static uint8_t pt[SESSION_MAX_PLAINTEXT_BYTES];
    handshake_ctx_t hs;
    memset(&hs, 0, sizeof hs);
    size_t out_len = 0, len = 0;
    const char *stage = "init";
    int rc = EX_FAIL;

    handshake_status_t hst = handshake_initiator_init(&hs, hid, hid_len, kp, &cs->pins, sid, sid_len);
    if (hst != HANDSHAKE_OK) { goto fail; }
    stage = "client-hello";
    hst = handshake_initiator_create_client_hello(&hs, tx + FRAME_HEADER_BYTES,
                                                  FRAME_MAX_PAYLOAD, &out_len);
    if (hst != HANDSHAKE_OK) { goto fail; }
    if (cs_send(cs, tx, out_len) != FRAME_OK) { goto fail_io; }
    stage = "server-hello";
    if (cs_recv(cs, rx, 1u, FRAME_MAX_SERVER_HELLO, &len) != FRAME_OK) {
        goto fail_io;
    }
    hst = handshake_initiator_verify_server_hello(&hs, rx + FRAME_HEADER_BYTES, len);
    if (hst != HANDSHAKE_OK) { goto fail; }
    stage = "client-auth";
    hst = handshake_initiator_create_client_auth(&hs, tx + FRAME_HEADER_BYTES,
                                                 FRAME_MAX_PAYLOAD, &out_len);
    if (hst != HANDSHAKE_OK) { goto fail; }
    if (cs_send(cs, tx, out_len) != FRAME_OK) { goto fail_io; }
    hst = handshake_initiator_finish(&hs);
    if (hst != HANDSHAKE_OK) { goto fail; }
    /* Captured BEFORE session_init consumes the context: ROTATE's digest binds
     * to it and nothing else can hand it back. */
    if (handshake_get_handshake_id(&hs, cs->hsid) != HANDSHAKE_OK) { goto fail_io; }

    {
        session_limits_t lim;
        session_default_limits(&lim);
        if (session_init_from_handshake(&cs->sess, &hs, &lim, NULL, NULL) != SESSION_OK) {
            stage = "session-init";
            goto fail_io;
        }
    }
    stage = "login-code";
    if (cs_recv(cs, rx, FRAME_CONFIRM_MIN, FRAME_CONFIRM_MAX, &len)
            != FRAME_OK) {
        goto fail_io;
    }
    {
        size_t pt_len = 0;
        if (session_open(&cs->sess, rx + FRAME_HEADER_BYTES, len, pt,
                         SESSION_OPEN_CAP_FOR(FRAME_CONFIRM_MAX), &pt_len) != SESSION_OK) {
            goto fail_io;
        }
        const authmsg_status_t as = authmsg_decode_login_code(pt, pt_len, &cs->code);
        sodium_memzero(pt, sizeof pt);
        if (as != AUTHMSG_OK) {
            if (!quiet) {
                fprintf(stderr, "%s %s: %s: %s\n", prog, sub, stage, authmsg_status_name(as));
            }
            goto fail_io;
        }
    }
    cs->live = 1;
    handshake_ctx_wipe(&hs);
    return EX_OK;

fail:
    if (!quiet) {
        fprintf(stderr, "%s %s: %s: %s\n", prog, sub, stage, hs_name(hst));
    }
fail_io:
    if (!quiet && hst == HANDSHAKE_OK) {
        fprintf(stderr, "%s %s: failed at %s\n", prog, sub, stage);
    }
    sodium_memzero(pt, sizeof pt);
    handshake_ctx_wipe(&hs);
    client_session_close(cs);
    return rc;
}

/* Sends BYE so the daemon releases the slot now rather than at its idle
 * deadline, then closes. Best effort: nothing depends on it arriving. */
static void client_say_bye(client_session_t *cs)
{
    uint8_t body[AUTHMSG_BYE_CONTENT_LEN];
    static uint8_t tx[FRAME_BUF_BYTES];
    size_t n = 0, sealed = 0;
    if (cs->live && authmsg_encode_bye(body, sizeof body, &n) == AUTHMSG_OK &&
        session_seal(&cs->sess, body, n, tx + FRAME_HEADER_BYTES, FRAME_MAX_PAYLOAD,
                     &sealed) == SESSION_OK) {
        (void)cs_send(cs, tx, sealed);
    }
    client_session_close(cs);
}

/* ---- the .ek.next state machine (spec 10.2) ------------------------------ */

/* What to do about a leftover <handle>.ek.next.
 *
 * Spec 10.2 says: "if it is unknown, the server never committed". That rule
 * CANNOT BE IMPLEMENTED, and implementing it as written would be dangerous.
 * Req 6 and 7.3 guarantee a client cannot distinguish an unknown key from a
 * revoked one from a wrong signature -- every one of them pins the decoy and
 * fails at the same point. "Unknown" is not observable, so "unknown therefore
 * the server never committed" is an inference from something the client never
 * learns.
 *
 * The sound rule is the contrapositive on the OTHER file, and it is stronger:
 *
 *     .ek authenticating PROVES the server did not commit -- there is exactly
 *     one active key per handle (the one_active_key index, spec 9.1) -- and
 *     only then may .ek.next be discarded. .ek.next failing proves nothing.
 *
 * So this never deletes on ambiguity. A stale file costs one confusing entry
 * in a directory; a wrong delete costs the only copy of a live key, and there
 * is no recovery path from that but re-enrolment by an administrator.
 *
 * Recorded as errata against 10.2 rather than silently deviated from. */
/* `ek_ok` / `next_ok` are "this file opened AND the daemon accepted it".
 * `next_present` distinguishes "no .ek.next" from "one that did not work".
 *
 * Exported (authd_cli.h) ONLY so a test can drive every combination without a
 * network round trip nobody can crash in the middle of. */
key_plan_t client_key_plan(int ek_ok, int next_present, int next_ok)
{
    if (ek_ok) {
        return KEY_PLAN_USE_EK;
    }
    if (next_present && next_ok) {
        return KEY_PLAN_PROMOTE_NEXT;
    }
    return KEY_PLAN_REFUSE;
}

static int cmd_client_keygen(int argc, char **argv, const char *prog)
{
    const char *dir = NULL, *pass_path = NULL;
    for (int i = 2; i < argc; i++) {
        const int has = (i + 1 < argc);
        if (strcmp(argv[i], "--dir") == 0 && has)                  { dir = argv[++i]; }
        else if (strcmp(argv[i], "--passphrase-file") == 0 && has) { pass_path = argv[++i]; }
        else { return unexpected(prog, "keygen", argv[i]); }
    }
    if (dir == NULL || pass_path == NULL) {
        return need(prog, "keygen", "--dir DIR --passphrase-file PATH");
    }

    /* Spec 3.1: handle = "d1" || 32 lowercase hex characters, from 16 random
     * bytes generated HERE, together with the keypair. No round trip is needed
     * to learn an identity, and 128 bits of unguessability is most of the
     * answer to enumeration -- the wire carries no user name at all. */
    uint8_t raw[16];
    char handle[35];
    randombytes_buf(raw, sizeof raw);
    handle[0] = 'd';
    handle[1] = '1';
    hexify(handle + 2, raw, sizeof raw);
    sodium_memzero(raw, sizeof raw);

    char ek[PATH_MAX], pub[PATH_MAX];
    char ek_name[64], pub_name[64];
    (void)snprintf(ek_name, sizeof ek_name, "%s.ek", handle);
    (void)snprintf(pub_name, sizeof pub_name, "%s.pub", handle);
    if (join(ek, sizeof ek, dir, ek_name) != 0 || join(pub, sizeof pub, dir, pub_name) != 0) {
        return need(prog, "keygen", "--dir DIR --passphrase-file PATH");
    }
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        return failed(prog, "keygen", dir, "cannot-create-directory");
    }
    uint8_t *pass = NULL;
    size_t pass_len = 0;
    int rc = read_pass(prog, "keygen", pass_path, &pass, &pass_len);
    if (rc != EX_OK) {
        return rc;
    }
    rc = seal_new_identity(prog, "keygen", ek, pub, (const uint8_t *)handle, strlen(handle),
                           (const char *)pass, pass_len, KDF_OPS_OPERATOR, KDF_MEM_256MIB, NULL);
    authd_secret_free(pass, pass_len);
    if (rc != EX_OK) {
        return rc;
    }
    printf("%s\n", handle);
    fprintf(stderr, "%s keygen: wrote %s (MLDSAEK1, mode 0600) and %s\n", prog, ek, pub);
    fprintf(stderr, "%s keygen: give %s to an administrator, who runs:\n"
                    "  authd_admin enroll-operator --socket ADMIN.SOCK --user YOU "
                    "--handle %s --pub %s\n"
                    "The secret key never leaves this machine.\n", prog, pub_name, handle, pub_name);
    return EX_OK;
}

/* Shared option parsing for login and rotate: they take the same connection
 * and identity arguments, and differ only in what they do with the session. */
typedef struct {
    const uint8_t *hid; size_t hid_len;
    const uint8_t *sid; size_t sid_len;
    const char *key_path;
    const char *pass_path;
    const char *server_pub;
    const char *unix_path;
    uint16_t port;
    /* §7.1: the opaque value the site put in its pre-login session. It rides
     * the WebSocket URL, so it means nothing on the raw tunnel listener --
     * which is exactly why the daemon binds SHA-256("") there. */
    const char *state;
} client_args_t;

static int parse_client_args(int argc, char **argv, const char *prog, const char *sub,
                             client_args_t *a)
{
    const char *handle = NULL, *server_id = NULL, *port_s = NULL;
    memset(a, 0, sizeof *a);
    for (int i = 2; i < argc; i++) {
        const int has = (i + 1 < argc);
        if (strcmp(argv[i], "--handle") == 0 && has)               { handle = argv[++i]; }
        else if (strcmp(argv[i], "--key") == 0 && has)             { a->key_path = argv[++i]; }
        else if (strcmp(argv[i], "--passphrase-file") == 0 && has) { a->pass_path = argv[++i]; }
        else if (strcmp(argv[i], "--server-id") == 0 && has)       { server_id = argv[++i]; }
        else if (strcmp(argv[i], "--server-pub") == 0 && has)      { a->server_pub = argv[++i]; }
        else if (strcmp(argv[i], "--unix") == 0 && has)            { a->unix_path = argv[++i]; }
        else if (strcmp(argv[i], "--state") == 0 && has)           { a->state = argv[++i]; }
        else if (strcmp(argv[i], "--port") == 0 && has)            { port_s = argv[++i]; }
        else { return unexpected(prog, sub, argv[i]); }
    }
    uint64_t port = 0;
    if (handle == NULL || a->key_path == NULL || a->pass_path == NULL || server_id == NULL ||
        a->server_pub == NULL || (a->unix_path == NULL) == (port_s == NULL) ||
        demo_parse_id(handle, &a->hid, &a->hid_len) != 0 ||
        demo_parse_id(server_id, &a->sid, &a->sid_len) != 0 ||
        (port_s != NULL && demo_parse_u64(port_s, 1u, 65535u, &port) != 0)) {
        return need(prog, sub,
                    "--handle H --key H.ek --passphrase-file PATH --server-id ID "
                    "--server-pub server.pub (--unix PATH | --port N) [--state S]");
    }
    a->port = (uint16_t)port;
    return EX_OK;
}

/* Decides which key file is live, completing an interrupted rename if that is
 * what happened, and returns the opened keypair.
 *
 * The probe is a REAL handshake against the daemon, not a local check: whether
 * a key is current is a fact the server holds, and "decrypts" says nothing
 * about it. That makes this the slow path -- but it only runs at all when a
 * .ek.next exists, which is the aftermath of an interrupted rotation.
 *
 * Only .ek authenticating lets the caller discard .ek.next. See
 * client_key_plan for why the spec's own wording cannot be used. */
static int client_resolve_key(const char *prog, const char *sub, const client_args_t *a,
                              const char *pass, size_t pass_len, const uint8_t *server_pk,
                              char *next_path, size_t next_cap, mldsa_keypair_t *kp_out)
{
    memset(kp_out, 0, sizeof *kp_out);
    if (snprintf(next_path, next_cap, "%s.next", a->key_path) < 0) {
        return EX_FAIL;
    }
    const int next_present = path_exists(next_path);

    /* The ordinary case: no interrupted rotation, so open .ek and go. */
    if (!next_present) {
        const keyfile_status_t ks = keyfile_open(a->key_path, a->hid, a->hid_len,
                                                 pass, pass_len, kp_out, NULL);
        if (ks != KEYFILE_OK) {
            return failed(prog, sub, a->key_path, keyfile_status_name(ks));
        }
        return EX_OK;
    }

    fprintf(stderr, "%s %s: %s exists -- a rotation was interrupted; asking the daemon "
                    "which key is live\n", prog, sub, next_path);

    int ek_ok = 0, next_ok = 0;
    mldsa_keypair_t ek_kp, next_kp;
    memset(&ek_kp, 0, sizeof ek_kp);
    memset(&next_kp, 0, sizeof next_kp);
    client_session_t probe;

    if (keyfile_open(a->key_path, a->hid, a->hid_len, pass, pass_len, &ek_kp, NULL) == KEYFILE_OK) {
        if (client_open_session(prog, sub, 1, &ek_kp, a->hid, a->hid_len, a->sid, a->sid_len,
                                server_pk, a->unix_path, a->port, a->state, &probe) == EX_OK) {
            ek_ok = 1;
            client_say_bye(&probe);
        }
    }
    if (!ek_ok &&
        keyfile_open(next_path, a->hid, a->hid_len, pass, pass_len, &next_kp, NULL) == KEYFILE_OK) {
        if (client_open_session(prog, sub, 1, &next_kp, a->hid, a->hid_len, a->sid, a->sid_len,
                                server_pk, a->unix_path, a->port, a->state, &probe) == EX_OK) {
            next_ok = 1;
            client_say_bye(&probe);
        }
    }

    const key_plan_t plan = client_key_plan(ek_ok, next_present, next_ok);
    int rc = EX_FAIL;
    switch (plan) {
    case KEY_PLAN_USE_EK:
        /* .ek is live, so the server never committed .ek.next. THIS is the only
         * proof that makes discarding it safe -- and the caller does the
         * discarding, because login should not delete files. */
        fprintf(stderr, "%s %s: %s is still the live key; %s was never committed\n",
                prog, sub, a->key_path, next_path);
        memcpy(kp_out, &ek_kp, sizeof ek_kp);
        memset(&ek_kp, 0, sizeof ek_kp);
        rc = EX_OK;
        break;
    case KEY_PLAN_PROMOTE_NEXT:
        /* The server committed and the rename was interrupted. Finish it. */
        if (keyfile_promote(next_path, a->key_path) != KEYFILE_OK) {
            (void)failed(prog, sub, a->key_path, "cannot-complete-rename");
            break;
        }
        fprintf(stderr, "%s %s: completed the interrupted rotation; %s now holds the live key\n",
                prog, sub, a->key_path);
        memcpy(kp_out, &next_kp, sizeof next_kp);
        memset(&next_kp, 0, sizeof next_kp);
        rc = EX_OK;
        break;
    case KEY_PLAN_REFUSE:
    default:
        /* Neither worked. Deleting either one now would be guessing with the
         * only copies of the identity, so nothing is touched. */
        fprintf(stderr, "%s %s: neither %s nor %s authenticates. NOTHING has been deleted; "
                        "an administrator must re-enrol this device.\n",
                prog, sub, a->key_path, next_path);
        break;
    }
    mldsa_keypair_free(&ek_kp);
    mldsa_keypair_free(&next_kp);
    return rc;
}

static int cmd_client_login(int argc, char **argv, const char *prog)
{
    client_args_t a;
    int rc = parse_client_args(argc, argv, prog, "login", &a);
    if (rc != EX_OK) { return rc; }

    /* The pinned server key, loaded BEFORE anything is sent. Spec 4: a client
     * MUST reject a ServerHello that is not signed by the pinned key -- that
     * is what makes this deployment phishing-resistant, the same property
     * WebAuthn gets from origin binding. A login without a pin would
     * authenticate this device to whatever answered the socket. */
    static uint8_t server_pk[MLDSA_PUBLIC_KEY_BYTES];
    const demo_keys_status_t ps = demo_keys_load_public(a.server_pub, a.sid, a.sid_len, server_pk);
    if (ps != DEMO_KEYS_OK) {
        return failed(prog, "login", a.server_pub, demo_keys_status_name(ps));
    }
    uint8_t *pass = NULL;
    size_t pass_len = 0;
    rc = read_pass(prog, "login", a.pass_path, &pass, &pass_len);
    if (rc != EX_OK) { return rc; }

    /* Every invocation of this tool is a "startup", so the interrupted-rename
     * recovery runs here too -- and in practice this is the command that
     * discovers one, not rotate. */
    char next_path[PATH_MAX];
    mldsa_keypair_t kp;
    rc = client_resolve_key(prog, "login", &a, (const char *)pass, pass_len, server_pk,
                            next_path, sizeof next_path, &kp);
    authd_secret_free(pass, pass_len);
    if (rc != EX_OK) { return rc; }

    client_session_t cs;
    rc = client_open_session(prog, "login", 0, &kp, a.hid, a.hid_len, a.sid, a.sid_len,
                             server_pk, a.unix_path, a.port, a.state, &cs);
    mldsa_keypair_free(&kp);
    if (rc != EX_OK) { return rc; }

    /* Base64url, spec 13: this is pasted into the site's form by a human, and
     * 43 unpadded URL-safe characters survive that trip where hex would be 64
     * and standard base64 would carry '+', '/' and '='. */
    char b64[sodium_base64_ENCODED_LEN(AUTHMSG_CODE_BYTES,
                                       sodium_base64_VARIANT_URLSAFE_NO_PADDING)];
    (void)sodium_bin2base64(b64, sizeof b64, cs.code.code, sizeof cs.code.code,
                            sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    printf("%s\n", b64);
    sodium_memzero(b64, sizeof b64);
    if ((cs.code.flags & AUTHMSG_FLAG_ROTATION_DUE) != 0u) {
        fprintf(stderr, "%s login: this key is due for rotation -- run `%s rotate`\n", prog, prog);
    }
    fprintf(stderr, "%s login: code valid for %lld more seconds; single use\n", prog,
            (long long)cs.code.code_expires - (long long)time(NULL));
    client_say_bye(&cs);
    return EX_OK;
}

static int cmd_client_rotate(int argc, char **argv, const char *prog)
{
    client_args_t a;
    int rc = parse_client_args(argc, argv, prog, "rotate", &a);
    if (rc != EX_OK) { return rc; }

    static uint8_t server_pk[MLDSA_PUBLIC_KEY_BYTES];
    const demo_keys_status_t ps = demo_keys_load_public(a.server_pub, a.sid, a.sid_len, server_pk);
    if (ps != DEMO_KEYS_OK) {
        return failed(prog, "rotate", a.server_pub, demo_keys_status_name(ps));
    }
    uint8_t *pass = NULL;
    size_t pass_len = 0;
    rc = read_pass(prog, "rotate", a.pass_path, &pass, &pass_len);
    if (rc != EX_OK) { return rc; }

    char next_path[PATH_MAX];
    mldsa_keypair_t old_kp;
    rc = client_resolve_key(prog, "rotate", &a, (const char *)pass, pass_len, server_pk,
                            next_path, sizeof next_path, &old_kp);
    if (rc != EX_OK) {
        authd_secret_free(pass, pass_len);
        return rc;
    }

    /* A leftover .ek.next that the probe did NOT promote is stale -- .ek
     * authenticated, which proves the server never committed it. Only now, on
     * that proof, is deleting it safe; never on the probe failing. */
    if (path_exists(next_path)) {
        (void)unlink(next_path);
    }

    /* Seal the new key BEFORE sending anything (spec 10.2). If everything
     * after this dies, the next invocation's probe decides which key is live
     * and completes or discards the rename -- there is no state in which the
     * only copy of a live key is gone. The new key is sealed under the SAME
     * passphrase: the probe has only one, and changing a passphrase during a
     * rotation is a different operation (`authd_admin rewrap`). */
    uint8_t new_pk[MLDSA_PUBLIC_KEY_BYTES];
    /* THIS DEVICE's public half, beside its own key -- derived from --key, not
     * from --server-pub, which names someone else's file in someone else's
     * directory. It is published only after the daemon accepts, so a failed
     * rotation never leaves a .pub claiming to be current. */
    char pub_path[PATH_MAX], pub_tmp[PATH_MAX];
    {
        const size_t kl = strlen(a.key_path);
        const int has_ek = (kl > 3u && strcmp(a.key_path + kl - 3u, ".ek") == 0);
        if (snprintf(pub_path, sizeof pub_path, "%.*s.pub",
                     (int)(has_ek ? kl - 3u : kl), a.key_path) < 0) {
            authd_secret_free(pass, pass_len);
            mldsa_keypair_free(&old_kp);
            return EX_FAIL;
        }
    }
    /* snprintf's return is CHECKED, not discarded: gcc refuses the discard at
     * both optimisation levels (-Werror=format-truncation), and it is right to
     * -- a truncated temp path would collide with something else. */
    {
        const int pn = snprintf(pub_tmp, sizeof pub_tmp, "%s.newpub.%ld",
                                next_path, (long)getpid());
        if (pn < 0 || (size_t)pn >= sizeof pub_tmp) {
            authd_secret_free(pass, pass_len);
            mldsa_keypair_free(&old_kp);
            return failed(prog, "rotate", next_path, "path-too-long");
        }
    }
    rc = seal_new_identity(prog, "rotate", next_path, pub_tmp, a.hid, a.hid_len,
                           (const char *)pass, pass_len, KDF_OPS_OPERATOR, KDF_MEM_256MIB,
                           new_pk);
    if (rc != EX_OK) {
        authd_secret_free(pass, pass_len);
        mldsa_keypair_free(&old_kp);
        return rc;
    }

    mldsa_keypair_t new_kp;
    memset(&new_kp, 0, sizeof new_kp);
    const keyfile_status_t ks = keyfile_open(next_path, a.hid, a.hid_len,
                                             (const char *)pass, pass_len, &new_kp, NULL);
    authd_secret_free(pass, pass_len);
    if (ks != KEYFILE_OK) {
        mldsa_keypair_free(&old_kp);
        return failed(prog, "rotate", next_path, keyfile_status_name(ks));
    }

    client_session_t cs;
    rc = client_open_session(prog, "rotate", 0, &old_kp, a.hid, a.hid_len, a.sid, a.sid_len,
                             server_pk, a.unix_path, a.port, a.state, &cs);
    if (rc != EX_OK) {
        mldsa_keypair_free(&old_kp);
        mldsa_keypair_free(&new_kp);
        return rc;
    }

    static uint8_t body[AUTHMSG_ROTATE_MAX_CONTENT];
    static uint8_t tx[FRAME_BUF_BYTES];
    static uint8_t rx[FRAME_BUF_BYTES];
    static uint8_t pt[SESSION_MAX_PLAINTEXT_BYTES];
    uint8_t dig[crypto_hash_sha256_BYTES];
    uint8_t sig_old[MLDSA_SIGNATURE_MAX_BYTES], sig_new[MLDSA_SIGNATURE_MAX_BYTES];
    size_t sol = 0, snl = 0, n = 0, sealed = 0, len = 0;
    rc = EX_FAIL;

    if (authmsg_rotate_digest(dig, AUTHMSG_LABEL_ROTATE_OLD, cs.hsid, 0u,
                              a.hid, a.hid_len, old_kp.public_key, new_pk) != AUTHMSG_OK ||
        mldsa_sign(sig_old, &sol, dig, sizeof dig, &old_kp) != 0 ||
        authmsg_rotate_digest(dig, AUTHMSG_LABEL_ROTATE_NEW, cs.hsid, 0u,
                              a.hid, a.hid_len, old_kp.public_key, new_pk) != AUTHMSG_OK ||
        mldsa_sign(sig_new, &snl, dig, sizeof dig, &new_kp) != 0 ||
        authmsg_encode_rotate(body, sizeof body, &n, 0u, a.hid, a.hid_len, new_pk,
                              sig_old, sol, sig_new, snl) != AUTHMSG_OK) {
        (void)failed(prog, "rotate", next_path, "cannot-build-rotate");
        goto out;
    }
    if (session_seal(&cs.sess, body, n, tx + FRAME_HEADER_BYTES, FRAME_MAX_PAYLOAD,
                     &sealed) != SESSION_OK ||
        cs_send(&cs, tx, sealed) != FRAME_OK) {
        (void)failed(prog, "rotate", next_path, "cannot-send-rotate");
        goto out;
    }
    if (cs_recv(&cs, rx, FRAME_MIN_RECORD, FRAME_MAX_RECORD, &len)
            != FRAME_OK) {
        /* No answer is NOT proof that nothing happened -- the daemon may have
         * committed and died before sealing the ACK. .ek.next stays. */
        fprintf(stderr, "%s rotate: no reply; %s is KEPT so the next run can resolve it\n",
                prog, next_path);
        goto out;
    }
    {
        size_t pl = 0;
        if (session_open(&cs.sess, rx + FRAME_HEADER_BYTES, len, pt, sizeof pt, &pl)
                != SESSION_OK) {
            fprintf(stderr, "%s rotate: the reply did not authenticate; %s is KEPT\n",
                    prog, next_path);
            goto out;
        }
        authmsg_rotate_ack_t ack;
        if (authmsg_decode_rotate_ack(pt, pl, &ack) != AUTHMSG_OK) {
            uint8_t code = 0;
            if (authmsg_decode_error(pt, pl, &code) == AUTHMSG_OK) {
                fprintf(stderr, "%s rotate: the daemon refused the rotation (error 0x%02x)\n",
                        prog, code);
            } else {
                fprintf(stderr, "%s rotate: unexpected reply\n", prog);
            }
            /* A refusal is not proof either -- the codes are coarse by design
             * (spec 6.5) and a daemon that committed then crashed answers
             * nothing at all. Keep the file; the probe decides next time. */
            fprintf(stderr, "%s rotate: %s is KEPT so the next run can resolve it\n",
                    prog, next_path);
            goto out;
        }
        /* The ACK must name THIS handle and the key we actually sealed.
         * Constant-time, because Req 3 says every digest comparison is. */
        uint8_t want_fp[crypto_hash_sha256_BYTES];
        crypto_hash_sha256(want_fp, new_pk, MLDSA_PUBLIC_KEY_BYTES);
        if (ack.handle_len != a.hid_len ||
            sodium_memcmp(ack.handle, a.hid, a.hid_len) != 0 ||
            sodium_memcmp(ack.fp_new, want_fp, sizeof want_fp) != 0) {
            fprintf(stderr, "%s rotate: the ACK names a different handle or key -- "
                            "NOT promoting %s\n", prog, next_path);
            goto out;
        }
        if (keyfile_promote(next_path, a.key_path) != KEYFILE_OK) {
            (void)failed(prog, "rotate", a.key_path, "cannot-replace-key");
            goto out;
        }
        /* Replace the device's own .pub so it does not go on naming a key the
         * server no longer accepts. Public data, so a plain rename: the
         * custody rules keyfile_promote enforces are about secrets. */
        if (rename(pub_tmp, pub_path) != 0) {
            fprintf(stderr, "%s rotate: the key rotated but %s could not be updated; "
                            "it still names the OLD key\n", prog, pub_path);
        }
        printf("%s\n", a.key_path);
        fprintf(stderr, "%s rotate: %s now holds the new key; the old one no longer "
                        "authenticates\n", prog, a.key_path);
        rc = EX_OK;
    }
out:
    (void)unlink(pub_tmp);
    sodium_memzero(dig, sizeof dig);
    sodium_memzero(pt, sizeof pt);
    mldsa_keypair_free(&old_kp);
    mldsa_keypair_free(&new_kp);
    client_say_bye(&cs);
    return rc;
}

static void client_usage(const char *prog)
{
    fprintf(stderr,
            "usage:\n"
            "  %s keygen --dir DIR --passphrase-file PATH\n"
            "  %s login  --handle H --key H.ek --passphrase-file PATH\n"
            "            --server-id ID --server-pub server.pub (--unix PATH | --port N) [--state S]\n"
            "  %s rotate --handle H --key H.ek --passphrase-file PATH\n"
            "            --server-id ID --server-pub server.pub (--unix PATH | --port N) [--state S]\n"
            "\n"
            "keygen prints the new device handle on stdout; login prints the login code as\n"
            "base64url, for pasting into the site's form. rotate replaces this device's key\n"
            "and keeps its identity: the new key is sealed to <key>.next BEFORE anything is\n"
            "sent, and renamed over <key> only when the daemon acknowledges. If a rotation\n"
            "is interrupted, the next login or rotate asks the daemon which key is live and\n"
            "finishes the job; nothing is ever deleted on a guess.\n"
            "Passphrases are FILES (mode 0600, owned by you): argv and the environment are\n"
            "readable by other processes on this machine.\n"
            "Exit: 0 ok, 1 operation failed, 2 usage, 3 configuration.\n",
            prog, prog, prog);
}

int authd_cli_client(int argc, char **argv)
{
    const char *prog = (argc > 0 && argv[0] != NULL) ? argv[0] : "authd_client";
    if (argc < 2) {
        client_usage(prog);
        return EX_USAGE;
    }
    if (strcmp(argv[1], "keygen") == 0) { return cmd_client_keygen(argc, argv, prog); }
    if (strcmp(argv[1], "login") == 0)  { return cmd_client_login(argc, argv, prog); }
    if (strcmp(argv[1], "rotate") == 0) { return cmd_client_rotate(argc, argv, prog); }
    fprintf(stderr, "%s: unknown subcommand '%s'\n", prog, argv[1]);
    client_usage(prog);
    return EX_USAGE;
}
