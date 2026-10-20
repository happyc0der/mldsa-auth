#ifndef MLDSA_AUTH_TESTS_KEY_WINDOWS_H
#define MLDSA_AUTH_TESTS_KEY_WINDOWS_H

/* Which windows of an ML-DSA-65 secret key are evidence that the key is
 * somewhere in the clear (V4-16, F105). One copy, shared by every test that
 * looks for a key by content -- test_authd_cli (the CLI's files),
 * test_authd_conn (the journal) and envelope_key_scan (a browser's profile,
 * V4-27) -- so the scans cannot drift apart. */

#include <stddef.h>

/* 1 if sk[w..w+len) is made wholly of SECRET bytes of an ML-DSA-65 secret key:
 * inside K = [32,64), or in s1|s2|t0 = [128,4032). rho = [0,32) IS pk[0..32)
 * and tr = [64,128) is SHAKE256(pk, 64), so a window touching either is partly
 * public -- and a mostly public one is no evidence: rho[17..32) || K[0] is in
 * every file holding the public key whenever K[0] happens to equal pk[32], one
 * key in 256. Keeping the windows that straddle (fuzz_keys's rule until V4-16,
 * F105) failed test_authd_cli at that rate. Every secret byte is still inside
 * some window that is looked for. */
static inline int sk_window_is_secret(size_t w, size_t len)
{
    return (w >= 32u && w + len <= 64u) || w >= 128u;
}

#endif
