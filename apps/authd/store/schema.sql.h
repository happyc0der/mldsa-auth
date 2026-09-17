#ifndef MLDSA_AUTHD_STORE_SCHEMA_H
#define MLDSA_AUTHD_STORE_SCHEMA_H

/*
 * The store schema, verbatim from the deployment spec (docs/mldsa-authd-spec.md
 * §9.1). It is a single C string so the DDL that runs is the DDL under review:
 * every CHECK, the foreign keys and -- the load-bearing one -- the partial
 * unique index `one_active_key` are here, not reconstructed in C. The
 * invariants of §9.2 (one active key per handle; a public key unique across
 * all devices and states forever) are enforced BY THIS SCHEMA, not by
 * application logic, so a bug in store.c cannot violate them silently.
 *
 * schema_version is stored in meta; STORE_SCHEMA_VERSION below is what this
 * build writes and requires. A store from a newer schema is refused rather
 * than silently mis-read.
 */

#define STORE_SCHEMA_VERSION 1

static const char STORE_SCHEMA_SQL[] =
    "CREATE TABLE IF NOT EXISTS meta("
    "  key TEXT PRIMARY KEY,"
    "  value BLOB"
    ");"
    "CREATE TABLE IF NOT EXISTS users("
    "  user_id BLOB PRIMARY KEY,"
    "  role TEXT CHECK(role IN('operator','user')),"
    "  status TEXT CHECK(status IN('active','disabled')),"
    "  created_at INT,"
    "  disabled_at INT,"
    "  disabled_reason BLOB,"
    "  recovery_fail_count INT DEFAULT 0,"
    "  recovery_locked_until INT DEFAULT 0"
    ");"
    "CREATE TABLE IF NOT EXISTS devices("
    "  handle BLOB PRIMARY KEY,"
    "  user_id BLOB NOT NULL REFERENCES users(user_id),"
    "  label BLOB,"
    "  status TEXT CHECK(status IN('active','revoked')),"
    "  enrolled_at INT,"
    "  enrolled_via TEXT,"
    "  enrolled_by TEXT,"
    "  revoked_at INT,"
    "  revoked_by TEXT,"
    "  revoked_reason BLOB,"
    "  last_seen INT"
    ");"
    "CREATE TABLE IF NOT EXISTS device_keys("
    "  key_id INTEGER PRIMARY KEY,"
    "  handle BLOB NOT NULL REFERENCES devices(handle),"
    "  pk BLOB UNIQUE,"
    "  pk_fp BLOB UNIQUE,"
    "  status TEXT CHECK(status IN('active','superseded','revoked')),"
    "  valid_from INT,"
    "  valid_to INT,"
    "  superseded_by_hsid BLOB"
    ");"
    "CREATE UNIQUE INDEX IF NOT EXISTS one_active_key"
    "  ON device_keys(handle) WHERE status='active';"
    "CREATE TABLE IF NOT EXISTS login_codes("
    "  code_hash BLOB PRIMARY KEY,"
    "  user_id BLOB,"
    "  handle BLOB,"
    "  handshake_id BLOB,"
    "  state_hash BLOB,"
    "  issued_at INT,"
    "  expires_at INT,"
    "  used_at INT"
    ");"
    "CREATE TABLE IF NOT EXISTS tokens("
    "  token_hash BLOB PRIMARY KEY,"
    "  user_id BLOB,"
    "  handle BLOB,"
    "  handshake_id BLOB,"
    "  issued_at INT,"
    "  expires_at INT,"
    "  idle_expires_at INT,"
    "  last_verified_at INT"
    ");"
    "CREATE TABLE IF NOT EXISTS recovery_codes("
    "  code_id INTEGER PRIMARY KEY,"
    "  user_id BLOB,"
    "  pwhash_str TEXT,"
    "  issued_at INT,"
    "  used_at INT,"
    "  used_from TEXT"
    ");"
    "CREATE TABLE IF NOT EXISTS enroll_tickets("
    "  ticket_hash BLOB PRIMARY KEY,"
    "  user_id BLOB,"
    "  issued_at INT,"
    "  expires_at INT,"
    "  used_at INT"
    ");"
    "CREATE TABLE IF NOT EXISTS audit("
    "  seq INTEGER PRIMARY KEY,"
    "  at INT,"
    "  event TEXT,"
    "  user_id BLOB,"
    "  handle BLOB,"
    "  detail TEXT,"
    "  prev_mac BLOB,"
    "  mac BLOB"
    ");";

#endif /* MLDSA_AUTHD_STORE_SCHEMA_H */
