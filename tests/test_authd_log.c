/*
 * V4-13d: the two log privacy switches (spec §15 `log_identities` /
 * `log_client_ip`, audit finding F14), checked on the exact bytes the logger
 * writes.
 *
 * Each mode is asserted in both directions: what must appear (a canary, so a
 * logger that wrote nothing at all cannot pass) and what must not (the raw
 * identifier, the host part of the address). The pseudonym callback here is a
 * stand-in with a known output; that the daemon's real one is the store's is
 * test_authd_store's and authd_e2e's to prove.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "authd_log.h"
#include "proxy_v2.h"

static int g_fail = 0;
static int g_checks = 0;

static void check(int ok, const char *what)
{
    g_checks++;
    printf("%s: %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) {
        g_fail = 1;
    }
}
#define CHECK(c, what) check((c) ? 1 : 0, (what))

/* Captures what one call writes. */
typedef struct { char *buf; size_t len; FILE *f; } cap_t;

static void cap_begin(cap_t *c)
{
    c->buf = NULL;
    c->len = 0;
    c->f = open_memstream(&c->buf, &c->len);
    if (c->f == NULL) {
        printf("FAIL: open_memstream\n");
        exit(1);
    }
    authd_log_init(c->f, AUTHD_LOG_INFO);
}

static const char *cap_end(cap_t *c)
{
    fflush(c->f);
    authd_log_init(stderr, AUTHD_LOG_ERROR);
    fclose(c->f);
    return c->buf != NULL ? c->buf : "";
}

/* The stand-in pseudonym: a fixed pattern XORed with the id's length and first
 * byte, so two different ids give two values the test can predict. */
static int g_calls = 0;
static size_t g_last_len = 0;
static int fake_pseudonym(void *ctx, const uint8_t *id, size_t id_len,
                          uint8_t out[AUTHD_LOG_PSEUDONYM_BYTES])
{
    (void)ctx;
    g_calls++;
    g_last_len = id_len;
    for (size_t i = 0; i < AUTHD_LOG_PSEUDONYM_BYTES; i++) {
        out[i] = (uint8_t)(0xa0u + i) ^ (uint8_t)id_len ^ (id_len > 0u ? id[0] : 0u);
    }
    return 0;
}

static int failing_pseudonym(void *ctx, const uint8_t *id, size_t id_len,
                             uint8_t out[AUTHD_LOG_PSEUDONYM_BYTES])
{
    (void)ctx; (void)id; (void)id_len;
    memset(out, 0x55, AUTHD_LOG_PSEUDONYM_BYTES);
    return -1;
}

static void expect_hex(char out[2u * AUTHD_LOG_PSEUDONYM_BYTES + 1u], const uint8_t *id, size_t n)
{
    uint8_t p[AUTHD_LOG_PSEUDONYM_BYTES];
    (void)fake_pseudonym(NULL, id, n, p);
    g_calls--;
    sodium_bin2hex(out, 2u * AUTHD_LOG_PSEUDONYM_BYTES + 1u, p, sizeof p);
}

static authd_addr_t v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    authd_addr_t x;
    memset(&x, 0, sizeof x);
    x.family = 4u;
    x.addr[0] = a; x.addr[1] = b; x.addr[2] = c; x.addr[3] = d;
    return x;
}

static authd_addr_t v6_sample(void)
{
    /* 2001:db8:1234:5678:9abc:def0:1:2 */
    static const uint8_t b[16] = { 0x20,0x01,0x0d,0xb8,0x12,0x34,0x56,0x78,
                                   0x9a,0xbc,0xde,0xf0,0x00,0x01,0x00,0x02 };
    authd_addr_t x;
    memset(&x, 0, sizeof x);
    x.family = 6u;
    memcpy(x.addr, b, sizeof b);
    return x;
}

static const uint8_t ALICE[] = "alice@example.org";
#define ALICE_LEN (sizeof ALICE - 1u)

static void test_words(void)
{
    authd_log_ids_t i;
    authd_log_ip_t p;
    CHECK(authd_log_ids_parse((const uint8_t *)"full", 4, &i) == 0 && i == AUTHD_LOG_IDS_FULL &&
          authd_log_ids_parse((const uint8_t *)"hashed", 6, &i) == 0 && i == AUTHD_LOG_IDS_HASHED &&
          authd_log_ids_parse((const uint8_t *)"off", 3, &i) == 0 && i == AUTHD_LOG_IDS_OFF,
          "words: log_identities accepts full, hashed, off");
    CHECK(authd_log_ip_parse((const uint8_t *)"full", 4, &p) == 0 && p == AUTHD_LOG_IP_FULL &&
          authd_log_ip_parse((const uint8_t *)"prefix", 6, &p) == 0 && p == AUTHD_LOG_IP_PREFIX &&
          authd_log_ip_parse((const uint8_t *)"off", 3, &p) == 0 && p == AUTHD_LOG_IP_OFF,
          "words: log_client_ip accepts full, prefix, off");
    CHECK(authd_log_ids_parse((const uint8_t *)"hash", 4, &i) != 0 &&
          authd_log_ids_parse((const uint8_t *)"hashedx", 7, &i) != 0 &&
          authd_log_ids_parse((const uint8_t *)"OFF", 3, &i) != 0 &&
          authd_log_ids_parse((const uint8_t *)"", 0, &i) != 0 &&
          authd_log_ip_parse((const uint8_t *)"prefi", 5, &p) != 0,
          "words: a prefix, an extension, another case and the empty word are refused");
    CHECK(strcmp(authd_log_ids_name(AUTHD_LOG_IDS_HASHED), "hashed") == 0 &&
          strcmp(authd_log_ip_name(AUTHD_LOG_IP_PREFIX), "prefix") == 0,
          "words: names round-trip");
}

static void test_set_privacy(void)
{
    CHECK(authd_log_set_privacy(AUTHD_LOG_IDS_HASHED, AUTHD_LOG_IP_FULL, NULL, NULL) == -1,
          "set: hashed without a pseudonym callback is refused");
    CHECK(authd_log_set_privacy((authd_log_ids_t)7, AUTHD_LOG_IP_FULL, NULL, NULL) == -1 &&
          authd_log_set_privacy(AUTHD_LOG_IDS_FULL, (authd_log_ip_t)7, NULL, NULL) == -1,
          "set: a value outside either enum is refused");
    /* a refusal changes nothing: the modes in force stay full */
    cap_t c;
    cap_begin(&c);
    authd_log_slot_id(AUTHD_LOG_INFO, "client-hello", 1u, ALICE, ALICE_LEN);
    const char *out = cap_end(&c);
    CHECK(strstr(out, "id=alice@example.org") != NULL, "set: after refusals, full is still in force");
    free(c.buf);
}

static void test_ids(void)
{
    cap_t c;
    const char *out;
    char want[64], hex[2u * AUTHD_LOG_PSEUDONYM_BYTES + 1u];

    /* FULL: the escaped identifier (the default, and the canary for the rest) */
    CHECK(authd_log_set_privacy(AUTHD_LOG_IDS_FULL, AUTHD_LOG_IP_FULL, NULL, NULL) == 0, "ids: set full");
    cap_begin(&c);
    authd_log_slot_id(AUTHD_LOG_INFO, "recovery-use", 3u, ALICE, ALICE_LEN);
    out = cap_end(&c);
    CHECK(strcmp(out, "info event=recovery-use slot=3 id=alice@example.org\n") == 0,
          "ids: full writes id=<identifier>");
    free(c.buf);

    /* HASHED: idh=<16 hex> from the callback, and the identifier nowhere */
    CHECK(authd_log_set_privacy(AUTHD_LOG_IDS_HASHED, AUTHD_LOG_IP_FULL, fake_pseudonym, NULL) == 0,
          "ids: set hashed");
    g_calls = 0;
    cap_begin(&c);
    authd_log_slot_id(AUTHD_LOG_INFO, "recovery-use", 3u, ALICE, ALICE_LEN);
    out = cap_end(&c);
    expect_hex(hex, ALICE, ALICE_LEN);
    snprintf(want, sizeof want, "info event=recovery-use slot=3 idh=%s\n", hex);
    CHECK(strcmp(out, want) == 0 && strlen(hex) == 16u, "ids: hashed writes idh=<16 hex> of the callback");
    CHECK(strstr(out, "alice") == NULL && strstr(out, " id=") == NULL,
          "ids: hashed writes neither the identifier nor an id= field");
    CHECK(g_calls == 1, "ids: hashed calls the pseudonym once per line");
    free(c.buf);

    /* the WHOLE identifier is hashed, not the escaped 64-byte field: two ids
     * that differ only past byte 64 are two people */
    {
        uint8_t longid[80];
        memset(longid, 'x', sizeof longid);
        g_last_len = 0;
        cap_begin(&c);
        authd_log_slot_id(AUTHD_LOG_INFO, "exchange", 0u, longid, sizeof longid);
        (void)cap_end(&c);
        free(c.buf);
        CHECK(g_last_len == sizeof longid, "ids: hashed passes the whole identifier, past the 64-byte field");
    }

    /* a pseudonym that cannot be computed is never replaced by the identifier */
    CHECK(authd_log_set_privacy(AUTHD_LOG_IDS_HASHED, AUTHD_LOG_IP_FULL, failing_pseudonym, NULL) == 0,
          "ids: set hashed with a failing callback");
    cap_begin(&c);
    authd_log_slot_id(AUTHD_LOG_WARN, "recovery-use", 2u, ALICE, ALICE_LEN);
    out = cap_end(&c);
    CHECK(strcmp(out, "warn event=recovery-use slot=2 idh=unavailable\n") == 0,
          "ids: a failed pseudonym is idh=unavailable, never a fallback to the identifier");
    free(c.buf);

    /* OFF: no identifier field at all */
    CHECK(authd_log_set_privacy(AUTHD_LOG_IDS_OFF, AUTHD_LOG_IP_FULL, NULL, NULL) == 0, "ids: set off");
    cap_begin(&c);
    authd_log_slot_id(AUTHD_LOG_INFO, "enroll", 4u, ALICE, ALICE_LEN);
    out = cap_end(&c);
    CHECK(strcmp(out, "info event=enroll slot=4\n") == 0, "ids: off writes the event with no identifier field");
    free(c.buf);

    /* the other fields are untouched by the switch: a fingerprint is a hash of
     * a PUBLIC key, required on every enrollment (§15), and stays */
    {
        uint8_t fp[32];
        memset(fp, 0xab, sizeof fp);
        cap_begin(&c);
        authd_log_fp(AUTHD_LOG_INFO, "enroll-fp", fp);
        out = cap_end(&c);
        CHECK(strstr(out, "fp=abababab") != NULL, "ids: off leaves fp= alone");
        free(c.buf);
    }
    (void)authd_log_set_privacy(AUTHD_LOG_IDS_FULL, AUTHD_LOG_IP_FULL, NULL, NULL);
}

static void test_ip(void)
{
    cap_t c;
    const char *out;
    authd_addr_t a4 = v4(203, 0, 113, 77);
    authd_addr_t a6 = v6_sample();
    const authd_addr_t a4_before = a4;

    CHECK(authd_log_set_privacy(AUTHD_LOG_IDS_FULL, AUTHD_LOG_IP_FULL, NULL, NULL) == 0, "ip: set full");
    cap_begin(&c);
    authd_log_slot_addr(AUTHD_LOG_INFO, "client-address", 5u, &a4, "admitted");
    out = cap_end(&c);
    CHECK(strcmp(out, "info event=client-address slot=5 src=203.0.113.77 detail=admitted\n") == 0,
          "ip: full writes the whole address");
    free(c.buf);

    CHECK(authd_log_set_privacy(AUTHD_LOG_IDS_FULL, AUTHD_LOG_IP_PREFIX, NULL, NULL) == 0, "ip: set prefix");
    cap_begin(&c);
    authd_log_slot_addr(AUTHD_LOG_INFO, "client-address", 5u, &a4, "admitted");
    out = cap_end(&c);
    CHECK(strcmp(out, "info event=client-address slot=5 src=203.0.113.0/24 detail=admitted\n") == 0,
          "ip: prefix writes an IPv4 address as its /24");
    free(c.buf);
    CHECK(memcmp(&a4, &a4_before, sizeof a4) == 0,
          "ip: prefix renders a copy -- the caller's address (the limiter's key) is unchanged");

    cap_begin(&c);
    authd_log_slot_addr(AUTHD_LOG_WARN, "refused-rate-limited", 6u, &a6, "addr");
    out = cap_end(&c);
    CHECK(strcmp(out, "warn event=refused-rate-limited slot=6 src=2001:db8:1234::/48 detail=addr\n") == 0,
          "ip: prefix writes an IPv6 address as its /48");
    CHECK(strstr(out, "5678") == NULL && strstr(out, "9abc") == NULL,
          "ip: nothing past the IPv6 /48 survives");
    free(c.buf);

    {
        authd_addr_t none;
        memset(&none, 0, sizeof none);
        cap_begin(&c);
        authd_log_slot_addr(AUTHD_LOG_WARN, "refused-no-client-address", 1u, &none, "local");
        out = cap_end(&c);
        CHECK(strcmp(out, "warn event=refused-no-client-address slot=1 src=none detail=local\n") == 0,
              "ip: prefix leaves `none` as it is, with no width");
        free(c.buf);
    }

    CHECK(authd_log_set_privacy(AUTHD_LOG_IDS_FULL, AUTHD_LOG_IP_OFF, NULL, NULL) == 0, "ip: set off");
    cap_begin(&c);
    authd_log_slot_addr(AUTHD_LOG_INFO, "client-address", 5u, &a4, "admitted");
    out = cap_end(&c);
    CHECK(strcmp(out, "info event=client-address slot=5 detail=admitted\n") == 0,
          "ip: off writes the event and its detail with no src field");
    free(c.buf);

    /* the two switches are independent */
    CHECK(authd_log_set_privacy(AUTHD_LOG_IDS_HASHED, AUTHD_LOG_IP_FULL, fake_pseudonym, NULL) == 0,
          "ip: set hashed ids with full addresses");
    cap_begin(&c);
    authd_log_slot_addr(AUTHD_LOG_INFO, "client-address", 5u, &a4, "admitted");
    out = cap_end(&c);
    CHECK(strstr(out, "src=203.0.113.77 ") != NULL, "ip: log_identities does not touch the address");
    free(c.buf);
    (void)authd_log_set_privacy(AUTHD_LOG_IDS_FULL, AUTHD_LOG_IP_FULL, NULL, NULL);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (sodium_init() < 0) {
        printf("FAIL: sodium_init\n");
        return 1;
    }
    test_words();
    test_set_privacy();
    test_ids();
    test_ip();
    printf("%d checks\n", g_checks);
    if (g_fail) {
        printf("FAILED\n");
        return 1;
    }
    printf("All checks passed\n");
    return 0;
}
