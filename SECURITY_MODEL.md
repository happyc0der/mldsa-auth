# Threat model — happyc0der/mldsa-auth

Built on the owner's own threat model, `docs/v4/threat-model.md` (V4-1), the daemon spec
`docs/mldsa-authd-spec.md` (§4 trust model, §5 requirements, §18 known limitations) and the
in-repo deployment files under `deploy/`. Facts marked **(owner)** come from those documents or
from the owner in chat; everything else is read from the code. No separate infrastructure
repository exists: `deploy/` (systemd units, Caddyfile, runbook) is the infrastructure.

## System overview

Intended deployment: one VPS, root + systemd. Browser or CLI → **Caddy** (TLS, PROXY v2 to a Unix
socket) → **`mldsa-authd`** (post-quantum handshake: ML-DSA-65 identities over hybrid
X25519+ML-KEM-768, ChaCha20-Poly1305 records) → issues a single-use login code → **the site**
(Node.js) exchanges it over `site.sock` for an opaque session token. Operators first, public users
second **(owner)**. Installable but not yet deployed **(owner, README)**.

## Components

| Name | Code | Notes |
|---|---|---|
| **protocol-lib** | `src/crypto/`, `src/protocol/`, `src/util/` | Handshake, transcript, key schedule, record layer, secure_mem; wraps liboqs + libsodium |
| **authd** | `apps/authd/` (except client_*, cli_prompt, passphrase*, `localcli.c`, `authd_admin.c`) | Daemon: listener, `proxy_v2.c`, `ws.c`, `evloop.c`, `authd_conn.c`, `ratelimit.c`, `tokens.c`, `recovery.c`, `localapi.c`, `keyfile.c` (MLDSAEK1), `store/` (SQLite) |
| **admin-cli** | `apps/authd/authd_admin.c`, `authd_cli.c`, `localcli.c` | Root operator tooling over `admin.sock` and the store |
| **device-client** | `apps/authd/client_core.c`, `client_cli.c`, `client_wasm.c`, `passphrase*.c`, `cli_prompt.c`, `web/module_entry.c` | CLI and wasm client, sealed device keys |
| **web-client** | `web/client/`, `web/pages/` | Browser pages, IndexedDB key store, enrollment/login/recovery flows |
| **reference-site** | `examples/site-node/` | Node site consuming tokens over `site.sock` |
| **demo-apps** | `apps/*.c` (auth_client, auth_server, demo_app, frame, net_io) | Reference TCP client/server for the protocol |
| **deploy** | `deploy/`, `cmake/` | systemd units + credentials, Caddyfile, dependency pinning |
| **tooling** | `tests/`, `tools/`, `formal/`, `bench/` | Not shipped |

## Trust boundaries (owner, threat-model.md)

1. Browser/CLI ↔ Caddy — TLS. Caddy trusted for availability and client IP, not confidentiality/auth (CLI). For browsers, whoever serves the page controls the key (F137).
2. Caddy ↔ daemon — Unix socket, `SO_PEERCRED` uid allowlist (`proxy_uids`), mandatory PROXY v2 preamble, fail closed.
3. Daemon ↔ site — `site.sock` (0660, site group) vs `admin.sock` (0600, root), peer-uid checks. Site is trusted enroller + token consumer, never holds key material.
4. Daemon ↔ store — same uid; transactional, MAC-chained audit.
5. Device ↔ its key — passphrase-sealed envelope (Argon2id); browser is the weakest link.

## Entry points

- **Network (unauthenticated, internet):** WebSocket `/authd/v1` via Caddy → `listener.c`, `proxy_v2.c`, `ws.c`, `authd_conn.c`, handshake/session parsing, `authmsg.c` (LOGIN_CODE, ROTATE).
- **Site socket (site uid):** `localapi.c` line protocol — EXCHANGE, VERIFY, enrollment, revocation.
- **Admin socket / CLI (root):** `authd_admin.c`, `localcli.c`.
- **Config + key files (root/systemd):** `authd_config.c`, `keyfile.c`, `$CREDENTIALS_DIRECTORY`.
- **Browser:** reference site HTTP endpoints (`examples/site-node/server.mjs`: `/api/recover`, login-code POST), pages under `web/pages/`.
- **Demo TCP server:** `apps/auth_server.c`.

## Assets (owner)

Server identity secret key (worst single loss — clients pin it); device secret keys; session tokens
(stored as SHA-256); login codes (hashed, 60 s); recovery codes (Argon2id); the store
(`/var/lib/mldsa-authd/store.sqlite3`); audit log (MAC chain + journald).

## Attackers that matter (owner)

- Passive network incl. harvest-now-decrypt-later — the reason the project exists.
- Active network attacker inside TLS — CLI must still be safe (pinned server key, mutual ML-DSA).
- Phishing site — must fail on pinned server identity.
- Unauthenticated internet client hitting the daemon (parsing, rate limits, enumeration, flooding).
- Compromised site process — must not mint tokens without a handshake or obtain any secret.
- XSS on the site origin — keeps tokens out of JS; key exposure while unlocked is known (F144).
- Stolen backup/disk image — must not yield the server key or usable tokens.

## Existing controls

Pinned server key; transcript-bound mutual ML-DSA; uniform responder / decoy pin + 10–50 µs time
floor (V4-8, V4-67); per-address + global token buckets and per-address conn cap before any
signature (V4-10b); socket separation with peer-uid checks; MLDSAEK1 + systemd credentials;
secure_mem/mlock; CSP `script-src 'self' 'wasm-unsafe-eval'`; HSTS; fuzzing, sanitizers, mutation
testing, ProVerif model; pinned dependencies verified against advisories.

## Out of scope / accepted risk (owner)

- **Root on the VPS** — "Nothing in this design" stops it; documented as accepted (no HSM/TPM). **Owner (chat, 2026-11-13): do not deprioritize findings that need root or a compromised Caddy/TLS — keep the scanner's severity.**
- **Compromised Caddy / TLS for browser users** serving malicious page code (F137) — documented as accepted; same owner instruction applies.
- Browser key storage without hardware backing; undetectable clone of a copied browser key blob.
- Traffic analysis beyond record padding; handles/server id visible to whoever sees protocol bytes (F142).
- ML-KEM-768's relative youth (hybrid mitigates).
- Shared-address lockout by one prober behind CGNAT (F81) — operator tunes rate limits.
- Single-host store, single-threaded daemon, no server key rotation (spec §18).
- Authorization after a session exists is the site's job.

## Owner priorities (chat, 2026-11-13)

- **All components matter equally**: `examples/site-node` (reference-site) and the demo TCP apps (demo-apps) are as important as the daemon. No component is out of scope.
- **Availability matters as much as confidentiality**: DoS against `mldsa-authd` (flooding, hangs, crashes, resource exhaustion) is not deprioritized.
- **No finding is lowered** for needing root, a compromised Caddy, or TLS compromise; keep the scanner's severity.
- Net effect for reranking: the owner ruled out no attacker, asset or surface, so findings keep the scanner's severity unless the owner says otherwise.

## Finding tags

`Component` (names above), `CWE`, and `Reference` — the project's own finding/decision ids the issue relates to (e.g. `F137`, `V4-68`, spec section).

## Open questions

- None outstanding.
