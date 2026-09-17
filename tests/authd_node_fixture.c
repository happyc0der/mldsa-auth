/*
 * A real daemon for the Node reference handler to talk to (V4-9a).
 *
 * The Node test needs an actual daemon with a site socket, a store, an
 * enrolled device and a live login code -- otherwise it would be testing a
 * mock, which proves nothing about the protocol. This program is that daemon:
 * it starts the harness in-process, enrolls a device, performs one real
 * handshake to obtain a genuine login code, prints the socket path and the
 * code as JSON, and then keeps the event loop running so Node can drive it.
 *
 * It exits on its own after a bounded time, so a wedged test can never leave
 * it behind.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>

#include "authd_harness.h"

int main(int argc, char **argv)
{
    const int seconds = (argc > 1) ? atoi(argv[1]) : 20;
    if (sodium_init() < 0) { return 1; }
    authd_log_init(stderr, AUTHD_LOG_ERROR);

    char dir[256];
    snprintf(dir, sizeof dir, "/tmp/authd-node-%ld", (long)getpid());
    if (mkdir(dir, 0700) != 0) { fprintf(stderr, "mkdir failed\n"); return 1; }

    static h_daemon_t d;
    if (h_start(&d, dir, "node.sqlite3", 1) != 0) { fprintf(stderr, "h_start failed\n"); return 1; }
    /* The harness starts on a FIXED fake clock, which is what makes the C
     * tests exact. Node is a separate process on the wall clock, so this
     * fixture switches to real time BEFORE issuing anything: otherwise the
     * login code is stamped in 2023, the serve loop advances to now, and every
     * exchange is instantly `expired`. (It did, on the first run.) */
    d.app.now_unix = (int64_t)time(NULL);

    static const uint8_t U[] = { 'u','1' };
    static const uint8_t H[] = { 'd','1','a','a' };
    mldsa_keypair_t kp;
    if (mldsa_keypair_generate(&kp) != 0) { return 1; }
    (void)store_add_user(d.store, U, sizeof U, STORE_ROLE_USER);
    if (store_enroll_device(d.store, H, sizeof H, U, sizeof U, kp.public_key,
                            "site", "fixture", NULL, 0) != STORE_OK) { return 1; }

    static h_client_t c;
    uint8_t code[32];
    if (h_login(&d, &c, H, sizeof H, &kp) != 0) { fprintf(stderr, "login failed\n"); return 1; }
    if (h_get_login_code(&d, &c, code) != 0) { fprintf(stderr, "no code\n"); return 1; }

    char b64[64];
    sodium_bin2base64(b64, sizeof b64, code, sizeof code, sodium_base64_VARIANT_URLSAFE_NO_PADDING);

    printf("{\"sock\":\"%s\",\"code\":\"%s\",\"user\":\"u1\",\"handle\":\"d1aa\"}\n", d.site_path, b64);
    fflush(stdout);

    /* Serve until the deadline. Real time here, because Node is a separate
     * process on the wall clock -- the injected clock is for the C tests. */
    const time_t deadline = time(NULL) + seconds;
    while (time(NULL) < deadline) {
        d.app.now_ms += 5u;
        d.app.now_unix = (int64_t)time(NULL);
        (void)evloop_run_once(&d.ev, 5, d.app.now_ms);
    }
    h_client_close(&c);
    mldsa_keypair_free(&kp);
    h_stop(&d);
    { char cmd[512]; snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir);
      if (system(cmd) != 0) { /* best-effort */ } }
    return 0;
}
