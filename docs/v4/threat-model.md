# Threat model — mldsa-auth as one site's login system (V4-1)

Scope: the deployment the owner intends. Browser or CLI → **Caddy** (TLS) →
**`mldsa-authd`** (this protocol) → local Unix socket → **the site** (Node.js),
on one VPS with root and systemd. Operators first, public end users second.

This document states what the post-quantum layer adds *inside* TLS, and —
more importantly — what it does not.

## Assets

| Asset | Where it lives | Loss means |
|---|---|---|
| Server identity secret key | `MLDSAEK1` envelope on disk; plaintext in daemon memory while running | Impersonate the site to every client; clients pin this key, so this is the worst single loss |
| Device secret keys | Operator laptop / browser IndexedDB, passphrase-sealed | Impersonate that user until the device is revoked |
| Session tokens | Store (as SHA-256) + the user's cookie | Ride an authenticated session until expiry or revocation |
| Login codes | Store (hashed), 60 s TTL | Exchange for a token, once, within the window |
| Recovery codes | Store (Argon2id) | Enroll a new device for that user |
| The store itself | `/var/lib/mldsa-authd/store.sqlite3` | Who may log in; the audit history |
| Audit log | `audit` table (MAC chain) + journald | Ability to detect and reconstruct an incident |

## Adversaries and what each gets

| Adversary | Gets | Stopped by |
|---|---|---|
| **Passive network, today** | Ciphertext only | TLS, and independently the record layer |
| **Passive network, recording for later ("harvest now, decrypt later")** | Nothing readable even after a CRQC, **provided ML-KEM-768 or X25519 holds** | The hybrid KEX — this is the reason the project exists — for what crosses the protocol's channel. What crosses only the site's HTTPS (recovery codes when shown and when typed, the invite, the session cookie, the login code's last hop) is as safe as TLS's key exchange: post-quantum only where it negotiates X25519MLKEM768 (V4-68, F137) |
| **Active network attacker inside TLS** (compromised CA, corporate MITM, hostile Wi‑Fi with a trusted root) | **CLI:** cannot impersonate the site: the client verifies a ServerHello signed by the **pinned** server key and rejects any other, and cannot impersonate a user without their device key. **Browser:** the page's code comes over that same TLS on every visit, so this attacker can serve code that never checks the pin and uses a key the user unlocks. Since V4-68 a genuine page logs in only with the key pinned at enrollment; that protects nobody once the page itself is the attacker's (F137) | CLI: mutual ML-DSA over a bound transcript, strictly stronger than TLS+password, and the main security argument for this design. Browser: TLS itself, with HSTS, CAA and certificate-transparency monitoring; the protocol cannot protect a page its attacker delivered |
| **Phishing site** | A user's client refuses to complete a handshake with any server that cannot sign as the pinned identity. No password exists to phish | Pinned server identity (WebAuthn-style origin binding, by signature) |
| **Compromised Caddy** | Sees ciphertext and can deny service; can lie about the client IP (rate limiting degrades); **cannot** read the protocol, forge a handshake, or mint a token. **For browser users it can:** it serves the pages, so it can serve code that uses a key the user unlocks (F137) | The protocol runs end-to-end inside the proxied stream, for the CLI; nothing in this design, for the browser |
| **Compromised site process** (Node) | Can enroll devices for any user and can read tokens it is given; **cannot** mint a token without a completed handshake, and cannot recover any device or server secret | Sockets are separated (`site.sock` vs `admin.sock`) with peer-uid checks; operator enrollment is impossible from the site's uid |
| **Stolen browser device, unlocked** | That user's sessions until revoked | Revocation; recovery codes; passphrase on the key blob |
| **Stolen backup / disk image / VPS snapshot** | The store (token *hashes*, not tokens) and the **encrypted** server key — useless without the credential, which lives outside `/var/lib` | `MLDSAEK1` + systemd credential separation |
| **Root on the VPS** | Everything: the key is in process memory, the store is readable, the daemon can be replaced | Nothing in this design. Stated plainly; encryption at rest buys separation of backups and images, not resistance to root |
| **XSS on the site's origin** | Can drive the logged-in session, and can read wasm memory while a key is unlocked; can exfiltrate the encrypted blob for offline guessing | Login-code exchange keeps the *token* out of JS; Argon2id slows offline guessing; neither is a substitute for not having XSS |
| **Identity enumeration** | Nothing useful: handles are 128-bit random and the responder's reply is uniform (decoy pin), in its bytes and, since V4-67, in the lookup's time (F135) | V4-8 decoy flow + random handles + the pin's 50 µs time floor |
| **Login flooding** | Denial of service | Per-address and global token buckets, a per-address connection cap and ledger capacity sized to rate — all implemented in V4-10b, keyed on the PROXY v2 address, and refusing with HTTP 429 before any signature is spent |

## Trust boundaries

1. **Browser ↔ Caddy** — TLS. For the CLI, Caddy is trusted for availability
   and for the client IP, not for confidentiality or authentication. A
   browser also trusts TLS, and so Caddy, for the page's code: whatever serves
   the page decides what runs where the key is unlocked (F137).
2. **Caddy ↔ daemon** — a Unix socket; the daemon verifies the proxy's uid
   (`SO_PEERCRED`) against an allowlist and requires a **PROXY protocol v2**
   preamble, which the proxy writes before the client is allowed to write a
   byte. A connection with no address, or an unverifiable one, is closed
   (fail closed). V4-2's S5 spike established that the stock Caddy binary can
   emit the preamble to a Unix upstream; the `X-Real-IP` arrangement the first
   draft of this document described was superseded by it and is not
   implemented (spec §7.2).
3. **Daemon ↔ site** — `site.sock` (0660, site's group) and `admin.sock`
   (0600, root). The site is a *trusted enroller* and a *token consumer*; it
   is never given key material.
4. **Daemon ↔ store** — same uid, same host; the store is the authority on who
   may log in, and every mutation is transactional and audited.
5. **Client device ↔ its key** — a passphrase-sealed envelope. On the browser
   this is the weakest link in the whole design and the enrollment page says so.

## What the PQ layer adds over "TLS + passwords", honestly

Adds: post-quantum confidentiality of the session against recorded traffic;
mutual authentication where the site never holds a secret that can impersonate
the user; phishing resistance by pinned server identity; device-bound
credentials with per-device revocation; no password database to leak.

Does **not** add: protection against a compromised endpoint, a compromised
site process, or root on the server; protection against traffic analysis
beyond record padding; anything about authorization once a session exists.
**For browser users, it does not add protection against whoever controls the
site's TLS:** the page's code arrives that way on every visit (F137, V4-68).
The CLI's code and pin are local, and it does not depend on TLS at all.

## Residual risks accepted for this deployment

Root compromise (no HSM); browser key storage without hardware backing;
browser users' trust in the page's code, which is trust in TLS, whose
certificates are classical signatures, so a future quantum computer able to
forge them could serve a page as the site (F137);
ML-KEM-768's relative youth (mitigated by the hybrid, which survives either
half failing); no clone detection for a copied browser key blob; single-agent
verification of the implementation until an external review is commissioned
(V4-14).
