/*
 * Reference TCP client (spec §7, Step 6). DEMO ONLY.
 *
 *   auth_client keygen  --id ID --dir DIR
 *   auth_client connect --id ID --key SKFILE --peer SERVER_ID=PUBFILE
 *                       [--port N] [--message TEXT]... [--timeout-ms N] [--idle-timeout-ms N]
 *
 * Dials 127.0.0.1 only, authenticates the server by ML-DSA-65 against the
 * single explicitly pinned key, and sends application data only after the
 * server's empty confirmation record has authenticated (spec §6.4.4). Each
 * message must come back as an authenticated echo; the connection ends with
 * an authenticated GOODBYE. Nothing secret or decrypted is ever logged.
 */

#include "demo_app.h"
#include "demo_keys.h"
#include "net_io.h"

#include <sodium.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_MESSAGES 16u

static keystore_t g_pins;

static void usage(void) {
    fprintf(stderr,
            "usage:\n"
            "  auth_client keygen  --id ID --dir DIR\n"
            "  auth_client connect --id ID --key SKFILE --peer SERVER_ID=PUBFILE\n"
            "                      [--port N] [--message TEXT]... [--timeout-ms N] [--idle-timeout-ms N]\n"
            "DEMO ONLY: connects to 127.0.0.1; demo key files are unencrypted.\n");
}

static int cmd_connect(int argc, char **argv) {
    const char *id_s = NULL;
    const char *key_path = NULL;
    const char *peer = NULL;
    const char *texts[MAX_MESSAGES];
    size_t n_msgs = 0;
    uint64_t port = DEMO_DEFAULT_PORT;
    uint64_t hs_timeout = DEMO_HANDSHAKE_TIMEOUT_MS_DEFAULT;
    uint64_t idle_timeout = DEMO_IDLE_TIMEOUT_MS_DEFAULT;

    for (int i = 2; i < argc; i++) {
        const char *a = argv[i];
        const int has_val = (i + 1 < argc);
        if (strcmp(a, "--id") == 0 && has_val) {
            id_s = argv[++i];
        } else if (strcmp(a, "--key") == 0 && has_val) {
            key_path = argv[++i];
        } else if (strcmp(a, "--peer") == 0 && has_val) {
            peer = argv[++i];
        } else if (strcmp(a, "--port") == 0 && has_val) {
            if (demo_parse_u64(argv[++i], 1, 65535, &port) != 0) {
                usage();
                return 2;
            }
        } else if (strcmp(a, "--message") == 0 && has_val) {
            if (n_msgs == MAX_MESSAGES) {
                fprintf(stderr, "client: at most %u --message options\n", (unsigned)MAX_MESSAGES);
                return 2;
            }
            texts[n_msgs++] = argv[++i];
        } else if (strcmp(a, "--timeout-ms") == 0 && has_val) {
            if (demo_parse_u64(argv[++i], 1, 600000u, &hs_timeout) != 0) {
                usage();
                return 2;
            }
        } else if (strcmp(a, "--idle-timeout-ms") == 0 && has_val) {
            if (demo_parse_u64(argv[++i], 1, 3600000u, &idle_timeout) != 0) {
                usage();
                return 2;
            }
        } else {
            fprintf(stderr, "client: unexpected argument '%s'\n", a);
            usage();
            return 2;
        }
    }
    const uint8_t *id = NULL;
    size_t id_len = 0;
    const uint8_t *peer_id = NULL;
    size_t peer_len = 0;
    const char *peer_path = NULL;
    if (id_s == NULL || key_path == NULL || peer == NULL || demo_parse_id(id_s, &id, &id_len) != 0 ||
        demo_split_pin(peer, &peer_id, &peer_len, &peer_path) != 0) {
        usage();
        return 2;
    }

    static const char default_text[] = "hello from the reference client";
    demo_message_t msgs[MAX_MESSAGES];
    if (n_msgs == 0) {
        texts[n_msgs++] = default_text;
    }
    for (size_t i = 0; i < n_msgs; i++) {
        const size_t len = strlen(texts[i]);
        if (len < 1u || len > DEMO_MAX_MESSAGE_BYTES) {
            fprintf(stderr, "client: message %zu must be 1..%u bytes\n", i + 1u, (unsigned)DEMO_MAX_MESSAGE_BYTES);
            return 2;
        }
        msgs[i].data = (const uint8_t *)texts[i];
        msgs[i].len = len;
    }

    (void)signal(SIGPIPE, SIG_IGN);

    int rc = 1;
    demo_buffers_t *buf = NULL;
    mldsa_keypair_t kp;
    memset(&kp, 0, sizeof(kp));
    keystore_init(&g_pins);

    demo_keys_status_t ks = demo_keys_load_identity(key_path, id, id_len, &kp);
    if (ks != DEMO_KEYS_OK) {
        fprintf(stderr, "client: cannot load identity '%s' from %s: %s\n", id_s, key_path,
                demo_keys_status_name(ks));
        goto out;
    }
    uint8_t pk[MLDSA_PUBLIC_KEY_BYTES];
    ks = demo_keys_load_public(peer_path, peer_id, peer_len, pk);
    if (ks != DEMO_KEYS_OK || keystore_add(&g_pins, peer_id, peer_len, pk) != KEYSTORE_OK) {
        fprintf(stderr, "client: cannot pin server key for '%.*s' from %s: %s\n", (int)peer_len,
                (const char *)peer_id, peer_path, demo_keys_status_name(ks));
        goto out;
    }
    buf = calloc(1, sizeof(*buf));
    if (buf == NULL) {
        fprintf(stderr, "client: out of memory\n");
        goto out;
    }

    net_conn_t conn;
    const net_status_t cs = net_connect_loopback((uint16_t)port, net_deadline_in(hs_timeout), &conn);
    if (cs != NET_OK) {
        fprintf(stderr, "client: cannot connect to 127.0.0.1:%u (%s)\n", (unsigned)port, net_status_name(cs));
        goto out;
    }

    demo_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.local_id = id;
    cfg.local_id_len = id_len;
    cfg.local_kp = &kp;
    cfg.pins = &g_pins;
    cfg.peer_id = peer_id;
    cfg.peer_id_len = peer_len;
    cfg.handshake_timeout_ms = hs_timeout;
    cfg.idle_timeout_ms = idle_timeout;

    demo_result_t res;
    rc = (demo_client_run(&cfg, &conn, msgs, n_msgs, buf, &res) == DEMO_OK) ? 0 : 1;

out:
    if (buf != NULL) {
        sodium_memzero(buf, sizeof(*buf));
        free(buf);
    }
    keystore_wipe(&g_pins);
    mldsa_keypair_free(&kp);
    return rc;
}

int main(int argc, char **argv) {
    if (sodium_init() < 0) {
        fprintf(stderr, "client: sodium_init failed\n");
        return 1;
    }
    if (argc >= 2 && strcmp(argv[1], "keygen") == 0) {
        return demo_cli_keygen(argc, argv, 2, "auth_client");
    }
    if (argc >= 2 && strcmp(argv[1], "connect") == 0) {
        return cmd_connect(argc, argv);
    }
    usage();
    return 2;
}
