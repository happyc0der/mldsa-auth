/*
 * Reference TCP server (spec §7, Step 6). DEMO ONLY.
 *
 *   auth_server keygen      --id ID --dir DIR
 *   auth_server migrate-key --id ID --in OLD.sk --out NEW.sk   (legacy MLDSASK1 -> MLDSASK2)
 *   auth_server serve  --id ID --key SKFILE --pin CLIENT_ID=PUBFILE [--pin ...]
 *                      [--port N] [--port-file PATH] [--once]
 *                      [--handshake-timeout-ms N] [--idle-timeout-ms N]
 *                      [--pad-bucket N]    record padding this peer applies (default 256)
 *
 * Listens on 127.0.0.1 only and handles one connection at a time with fresh
 * per-connection handshake and session state; the pending-handshake ledger
 * lives for the whole process (spec §6.3.6, confinement). Clients are
 * authenticated only by ML-DSA-65 against explicitly pinned public keys --
 * never by address. Nothing secret or decrypted is ever logged.
 */

#include "demo_app.h"
#include "demo_keys.h"
#include "net_io.h"

#include <sodium.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ACCEPT_POLL_MS 1000u
#define SERVER_PENDING_CAPACITY 16u
#define LISTEN_BACKLOG 4

static volatile sig_atomic_t g_stop = 0;

static void on_stop(int sig) {
    (void)sig;
    g_stop = 1;
}

/* Large, process-lifetime objects live in static storage. */
static keystore_t g_pins;
static handshake_pending_store_t g_store;

static void usage(void) {
    fprintf(stderr,
            "usage:\n"
            "  auth_server keygen      --id ID --dir DIR\n"
            "  auth_server migrate-key --id ID --in OLD.sk --out NEW.sk\n"
            "  auth_server serve  --id ID --key SKFILE --pin CLIENT_ID=PUBFILE [--pin ...]\n"
            "                     [--port N] [--port-file PATH] [--once]\n"
            "                     [--handshake-timeout-ms N] [--idle-timeout-ms N]\n"
            "                     [--pad-bucket 1|16|64|256|1024|4096]\n"
            "DEMO ONLY: listens on 127.0.0.1; demo key files are unencrypted.\n");
}

static int cmd_serve(int argc, char **argv) {
    const char *id_s = NULL;
    const char *key_path = NULL;
    const char *port_file = NULL;
    const char *pins[KEYSTORE_MAX_ENTRIES];
    size_t n_pins = 0;
    uint64_t port = DEMO_DEFAULT_PORT;
    uint64_t hs_timeout = DEMO_HANDSHAKE_TIMEOUT_MS_DEFAULT;
    uint64_t idle_timeout = DEMO_IDLE_TIMEOUT_MS_DEFAULT;
    uint64_t pad_bucket = 0; /* 0 = library default (256) */
    int once = 0;

    for (int i = 2; i < argc; i++) {
        const char *a = argv[i];
        const int has_val = (i + 1 < argc);
        if (strcmp(a, "--id") == 0 && has_val) {
            id_s = argv[++i];
        } else if (strcmp(a, "--key") == 0 && has_val) {
            key_path = argv[++i];
        } else if (strcmp(a, "--pin") == 0 && has_val) {
            if (n_pins == KEYSTORE_MAX_ENTRIES) {
                fprintf(stderr, "server: at most %u --pin options\n", (unsigned)KEYSTORE_MAX_ENTRIES);
                return 2;
            }
            pins[n_pins++] = argv[++i];
        } else if (strcmp(a, "--port") == 0 && has_val) {
            if (demo_parse_u64(argv[++i], 0, 65535, &port) != 0) {
                usage();
                return 2;
            }
        } else if (strcmp(a, "--port-file") == 0 && has_val) {
            port_file = argv[++i];
        } else if (strcmp(a, "--once") == 0) {
            once = 1;
        } else if (strcmp(a, "--handshake-timeout-ms") == 0 && has_val) {
            if (demo_parse_u64(argv[++i], 1, HANDSHAKE_PENDING_TTL_MS_DEFAULT, &hs_timeout) != 0) {
                usage();
                return 2;
            }
        } else if (strcmp(a, "--idle-timeout-ms") == 0 && has_val) {
            if (demo_parse_u64(argv[++i], 1, 3600000u, &idle_timeout) != 0) {
                usage();
                return 2;
            }
        } else if (strcmp(a, "--pad-bucket") == 0 && has_val) {
            if (demo_parse_u64(argv[++i], 1, SESSION_PAD_BUCKET_MAX, &pad_bucket) != 0 ||
                !demo_pad_bucket_valid((uint32_t)pad_bucket)) {
                fprintf(stderr, "server: --pad-bucket must be one of 1, 16, 64, 256, 1024, 4096\n");
                return 2;
            }
        } else {
            fprintf(stderr, "server: unexpected argument '%s'\n", a);
            usage();
            return 2;
        }
    }
    const uint8_t *id = NULL;
    size_t id_len = 0;
    if (id_s == NULL || key_path == NULL || n_pins == 0 || demo_parse_id(id_s, &id, &id_len) != 0) {
        usage();
        return 2;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_stop; /* no SA_RESTART: blocking waits return EINTR and re-check g_stop */
    sigemptyset(&sa.sa_mask);
    (void)sigaction(SIGINT, &sa, NULL);
    (void)sigaction(SIGTERM, &sa, NULL);
    (void)signal(SIGPIPE, SIG_IGN);

    int rc = 1;
    int listen_fd = -1;
    int port_file_created = 0;
    demo_buffers_t *buf = NULL;
    mldsa_keypair_t kp;
    memset(&kp, 0, sizeof(kp));
    keystore_init(&g_pins);

    demo_keys_status_t ks = demo_keys_load_identity(key_path, id, id_len, &kp);
    if (ks != DEMO_KEYS_OK) {
        fprintf(stderr, "server: cannot load identity '%s' from %s: %s\n", id_s, key_path,
                demo_keys_status_name(ks));
        goto out;
    }
    for (size_t i = 0; i < n_pins; i++) {
        const uint8_t *pin_id = NULL;
        size_t pin_len = 0;
        const char *pin_path = NULL;
        uint8_t pk[MLDSA_PUBLIC_KEY_BYTES];
        if (demo_split_pin(pins[i], &pin_id, &pin_len, &pin_path) != 0) {
            fprintf(stderr, "server: bad --pin '%s' (expected CLIENT_ID=PUBFILE)\n", pins[i]);
            goto out;
        }
        ks = demo_keys_load_public(pin_path, pin_id, pin_len, pk);
        if (ks != DEMO_KEYS_OK) {
            fprintf(stderr, "server: cannot load pinned key for '%.*s' from %s: %s\n", (int)pin_len,
                    (const char *)pin_id, pin_path, demo_keys_status_name(ks));
            goto out;
        }
        const keystore_status_t add = keystore_add(&g_pins, pin_id, pin_len, pk);
        if (add == KEYSTORE_ERR_KEY_MISMATCH) {
            /* Security Req 4.7: a different key for a pinned id is rejected and logged. */
            fprintf(stderr, "server: REJECTED pin for '%.*s': already pinned with a DIFFERENT key\n", (int)pin_len,
                    (const char *)pin_id);
            goto out;
        }
        if (add != KEYSTORE_OK && add != KEYSTORE_OK_ALREADY_PRESENT) {
            fprintf(stderr, "server: cannot pin '%.*s' (keystore status %d)\n", (int)pin_len, (const char *)pin_id,
                    (int)add);
            goto out;
        }
    }
    if (handshake_pending_store_init(&g_store, SERVER_PENDING_CAPACITY, HANDSHAKE_PENDING_TTL_MS_DEFAULT, NULL,
                                     NULL) != PENDING_OK) {
        fprintf(stderr, "server: cannot initialize the pending-handshake store\n");
        goto out;
    }
    buf = calloc(1, sizeof(*buf));
    if (buf == NULL) {
        fprintf(stderr, "server: out of memory\n");
        goto out;
    }

    uint16_t bound = 0;
    if (net_listen_loopback((uint16_t)port, LISTEN_BACKLOG, &listen_fd, &bound) != NET_OK) {
        fprintf(stderr, "server: cannot listen on 127.0.0.1:%u\n", (unsigned)port);
        goto out;
    }
    if (port_file != NULL) {
        if (demo_publish_port_file(port_file, bound) != 0) {
            fprintf(stderr, "server: cannot create port file %s (it must not already exist)\n", port_file);
            goto out;
        }
        port_file_created = 1;
    }
    fprintf(stderr, "server: identity '%s' listening on 127.0.0.1:%u (loopback only; one connection at a time; "
                    "%zu pinned client key(s))\n",
            id_s, (unsigned)bound, keystore_count(&g_pins));

    demo_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.local_id = id;
    cfg.local_id_len = id_len;
    cfg.local_kp = &kp;
    cfg.pins = &g_pins;
    cfg.handshake_timeout_ms = hs_timeout;
    cfg.idle_timeout_ms = idle_timeout;
    cfg.pad_bucket = (uint32_t)pad_bucket;

    rc = once ? 1 : 0;
    while (!g_stop) {
        net_conn_t conn;
        const net_status_t as = net_accept(listen_fd, net_deadline_in(ACCEPT_POLL_MS), &conn);
        if (as == NET_TIMEOUT) {
            continue;
        }
        if (as != NET_OK) {
            fprintf(stderr, "server: accept failed (%s)\n", net_status_name(as));
            rc = 1;
            break;
        }
        demo_result_t res;
        (void)demo_server_handle_connection(&cfg, &g_store, &conn, buf, &res);
        if (once) {
            rc = (res.status == DEMO_OK) ? 0 : 1;
            break;
        }
    }

out:
    if (buf != NULL) {
        sodium_memzero(buf, sizeof(*buf));
        free(buf);
    }
    net_close_fd(&listen_fd);
    if (port_file_created) {
        (void)unlink(port_file);
    }
    handshake_pending_store_wipe(&g_store);
    keystore_wipe(&g_pins);
    mldsa_keypair_free(&kp);
    return rc;
}

int main(int argc, char **argv) {
    if (sodium_init() < 0) {
        fprintf(stderr, "server: sodium_init failed\n");
        return 1;
    }
    if (argc >= 2 && strcmp(argv[1], "keygen") == 0) {
        return demo_cli_keygen(argc, argv, 2, "auth_server");
    }
    if (argc >= 2 && strcmp(argv[1], "migrate-key") == 0) {
        return demo_cli_migrate_key(argc, argv, 2, "auth_server");
    }
    if (argc >= 2 && strcmp(argv[1], "serve") == 0) {
        return cmd_serve(argc, argv);
    }
    usage();
    return 2;
}
