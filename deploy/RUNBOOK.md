# Deploying mldsa-authd

**Part I (steps 1–12), milestone A:** operators log in with `authd_client`
through an SSH tunnel. One host, systemd, root available for the install.
**Part II (steps 13–18), milestone B:** the same daemon opened to the public —
people enrolling and logging in from a browser, phones included, through your
site behind the TLS proxy. Do Part I first; Part II only adds to it.

Everything below has been checked as far as it can be without your host: the
unit passes systemd's own analysers, the hardened binary is built and gated on
x86_64 Linux in CI, the offline build is proven with the network switched off,
and the backup/restore drill runs end to end. **What has not been checked is
your machine.** The steps are the part only you can run; each says what it
should print, so you can tell a success from a silence.

---

## 0. What you need

- A Linux host with systemd ≥ 250 (`systemd-analyze --version`) and root.
- A TLS proxy. Caddy is what `deploy/Caddyfile.example` is written and tested
  for; anything that speaks **PROXY protocol v2 to a Unix upstream** works.
- A build host — the same machine is fine. **The build path must not contain
  spaces** (libsodium's libtool cannot handle them; this is unpatchable, and it
  is why `/opt/build/mldsa-auth` appears below rather than anything prettier).

## 1. Build

Release, with a **named** CPU target. Never `auto`: that is `-march=native`,
and a binary built on one machine can fault with an illegal instruction on
another of the same family.

```bash
cd /opt/build/mldsa-auth
cmake -S . -B build-release \
      -DCMAKE_BUILD_TYPE=Release \
      -DMLDSA_OQS_OPT_TARGET=x86-64-v3
cmake --build build-release -j"$(nproc)"
```

`x86-64-v3` covers anything from roughly 2015 onward (AVX2). If your VPS is
older or you do not know, use `generic` — it gives up liboqs's AVX2 backends
and works everywhere.

**Offline or air-gapped?** Fetch the dependencies once on a networked machine
and carry the cache over; every hash and commit pin is still enforced:

```bash
sh deploy/fetch-deps.sh /opt/mldsa-deps        # networked machine, once
# carry /opt/mldsa-deps across, then, AS THE USER WHO WILL BUILD:
chown -R "$(id -un)" /opt/mldsa-deps
cmake -S . -B build-release -DMLDSA_DEPS_CACHE=/opt/mldsa-deps ...
```

The `chown` is not housekeeping. git refuses to read a repository owned by
another user, so a cache fetched as you and built as root stops the build
dead — the configure step says so by name and tells you this command, but it
is cheaper to get right the first time. Three things are still checked on
every offline configure, and none of them is relaxed by being offline: the
cache holds the pinned liboqs commit, the populated tree holds it too, and
both archives match their hashes. A cache that has drifted is refused before
anything is unpacked.

## 2. Check what you built

```bash
tools/audit/check_hardening.sh build-release --require
tools/check_backend_symbols.sh build-release
```

The first must end `OK: every discovered executable carries the full hardening
set [Linux]`. On macOS it would pass on three properties out of five — RELRO
and BIND_NOW do not exist in Mach-O — so this check means what it says only
here.

## 3. Install

```bash
sudo cmake --install build-release --prefix /usr/local --component mldsa-authd
```

Installs `mldsa-authd`, `authd_admin`, `authd_client` into
`/usr/local/bin/`, and the unit, config and Caddyfile examples into
`/usr/local/share/mldsa-authd/`.

## 4. The service user and its directories

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin mldsa-authd
sudo install -d -o mldsa-authd -g mldsa-authd -m 0700 /var/lib/mldsa-authd
sudo install -d -o root -g root -m 0700 /etc/mldsa-authd
```

`/run/mldsa-authd/` is **not** created here: systemd's `RuntimeDirectory=`
makes it at start and removes it at stop, so a crash never leaves a stale
directory with the wrong mode.

Add the proxy's user to the daemon's group so it can reach the 0660 socket
(Caddy usually runs as `caddy`):

```bash
sudo usermod -aG mldsa-authd caddy
```

## 5. Create the identity and the store

```bash
sudo -u mldsa-authd authd_admin init \
     --dir /var/lib/mldsa-authd \
     --server-id authd \
     --passphrase-file /var/lib/mldsa-authd/pass
```

Prints four paths and a NOTE. **`server.pub` is what every client pins** —
copy it to your operators now; a client that does not pin it will accept any
server (spec §4).

`init` refuses to run if a key, store or passphrase file already exists, and
names which. That is deliberate: re-running it against an existing store would
re-derive the audit key and silently break the chain.

## 6. Move the passphrase into a credential, and delete the plaintext

```bash
sudo systemd-creds encrypt --name=passphrase \
     /var/lib/mldsa-authd/pass /etc/mldsa-authd/passphrase.cred
sudo chmod 0600 /etc/mldsa-authd/passphrase.cred
sudo shred -u /var/lib/mldsa-authd/pass
```

Where the host has a TPM, `systemd-creds` binds the credential to it. **Keep an
offline copy of the passphrase somewhere safe first:** there is no escrow and
no recovery path — losing it makes `server.ek` and the store unopenable.

## 7. Configure

```bash
sudo cp /usr/local/share/mldsa-authd/authd.conf.example /etc/mldsa-authd/authd.conf
sudo chmod 0600 /etc/mldsa-authd/authd.conf
sudo -e /etc/mldsa-authd/authd.conf      # set site_uids and proxy_uids
sudo mldsa-authd --config /etc/mldsa-authd/authd.conf --check-config
```

The last command prints the settings it resolved. **Read the
`proxy_protocol=` field.** If it says `none`, your proxy-facing listener has no
client address and the rate limiter is off — which is a passing check and a
broken deployment (audit finding F63).

`site_uids` must be the uid your site process runs as: `id -u www-data`.
`proxy_uids` must be the proxy's: `id -u caddy`.

The same line ends with `log_identities=` and `log_client_ip=`. The example sets
`hashed` and `prefix`, which is what Part II wants; an operators-only deployment
may prefer `full` for both, and nothing else changes (step 15 says what each
setting writes).

## 8. Install the unit

```bash
sudo cp /usr/local/share/mldsa-authd/mldsa-authd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemd-analyze verify /etc/systemd/system/mldsa-authd.service
sudo systemd-analyze security mldsa-authd.service
```

`verify` should print **nothing**. It exits 0 either way — an unknown directive
is only a warning — so the absence of output is the signal, not the status.
`security` should report an exposure level around **1.7**.

**If you raised `max_slots`,** raise `LimitMEMLOCK` with it: the requirement is
`4 KiB × 10 × max_slots`.

| `max_slots` | required | set `LimitMEMLOCK` to at least |
|---|---|---|
| 256 (default) | 10 MiB | 32M |
| 1024 | 40 MiB | 64M |
| 2048 | 80 MiB | 128M |
| 4096 (ceiling) | 160 MiB | 256M |

## 9. Start it

```bash
sudo systemctl enable --now mldsa-authd
journalctl -u mldsa-authd -n 30
```

You want `event=started`, one `event=listening-*` per configured listener, and
`event=memlock-limit`. **If `memlock-limit` is at `warn`**, the limit is below
the requirement and the daemon's secrets can be swapped to disk — fix
`LimitMEMLOCK` and restart. Nothing else reports this: libsodium hands back
unlocked memory without an error.

## 10. The proxy

```bash
sudo cp /usr/local/share/mldsa-authd/Caddyfile.example /etc/caddy/Caddyfile
sudo -e /etc/caddy/Caddyfile          # set your real hostname
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

`proxy_protocol v2` in the upstream transport is load-bearing: without it the
daemon has no client address and refuses every connection (Req 12).

## 11. Enrol yourself and log in

On your laptop:

```bash
authd_client keygen --dir ~/.mldsa --passphrase-prompt
```

It asks at the terminal, twice, with nothing echoed, and refuses a passphrase
the policy calls weak — at least 12 characters, not a common password, not
predictable — saying why in the words the browser uses. (`--passphrase-file`
works too, for a script, and is held to the same policy; a file holding a
person's passphrase is a copy of it at rest, so prefer the prompt.)

Send the printed handle and `<handle>.pub` to the server. There:

```bash
sudo -u mldsa-authd authd_admin enroll-operator \
     --socket /run/mldsa-authd/admin.sock \
     --user you --handle <handle> --pub <handle>.pub --label "laptop"
```

Back on the laptop, through an SSH tunnel to the loopback listener:

```bash
ssh -L 8443:127.0.0.1:8443 your-vps
authd_client login --handle <handle> --key ~/.mldsa/<handle>.ek \
    --passphrase-prompt --server-id authd \
    --server-pub ./server.pub --port 8443
```

A 43-character base64url login code means the whole path works.

## 12. Backups, and proving they are intact

```bash
sudo -u mldsa-authd authd_admin backup \
     --socket /run/mldsa-authd/admin.sock \
     --path /var/lib/mldsa-authd/backups/$(date +%F).sqlite3
```

`--path` must be absolute: the daemon resolves it, not your shell. The backup
is 0600, like the store.

Verify the audit chain — on the live store or on any backup, with the daemon
running or stopped:

```bash
sudo -u mldsa-authd authd_admin audit-verify \
     --store /var/lib/mldsa-authd/store.sqlite3 \
     --key /var/lib/mldsa-authd/server.ek \
     --passphrase-file /run/credentials/mldsa-authd.service/passphrase \
     --server-id authd
```

It prints the head MAC and an entry count. **Record the head MAC somewhere off
this host** — the chain detects tampering, but only if you have something to
compare against; that is the "second trust domain" spec §9.2 asks for. Running
this on a timer and mailing the output is enough.

A restore is a file copy: stop the service, replace `store.sqlite3`, start it.
Run `audit-verify` before you trust it.

---

# Part II — public users

The daemon does not change. What changes is who reaches it: people, in a
browser, often on a phone behind a carrier's shared address, whose identifiers
are personal data. Six steps, in order.

## 13. Build the browser module

On the build host, with **Emscripten 6.0.9 exactly** (configure refuses any
other version — the module's claim is that it reproduces the native
known-answer test byte for byte):

```bash
cd /opt/build/mldsa-auth
emcmake cmake -S . -B build-wasm -DCMAKE_BUILD_TYPE=Release
cmake --build build-wasm -j"$(nproc)"
ctest --test-dir build-wasm
```

`ctest` must report `100% tests passed out of 3`: the two known-answer tests
and the module gates (its exact export list, and no filesystem or dynamic
code). The result is `build-wasm/web/mldsa_client.{mjs,wasm}`, about 300 KB together (V4-13d: 288,109 + 13,169 bytes).

## 14. The site

The page runs the client; **your site** decides who may have an account and
turns a login code into a session. `examples/site-node/server.mjs` is a
complete reference — `node:http`, no dependencies — and it is what the tests
drive in a real browser. Use it, or hold your own site to the same four rules:

1. **A fresh `state` per login**, kept in the visitor's server-side session and
   put in the WebSocket URL; `EXCHANGE` must present it (spec §7.1, Req 5), so a
   code cannot be replayed into someone else's session.
2. **The login code arrives in a POST body on your own origin** — never in a
   URL, so never in a proxy log, a `Referer` or history (spec §14).
3. **Every POST must carry your `Origin`**, on a session cookie that is
   `HttpOnly; SameSite=Strict; Secure`.
4. **The token stays on the server.** Page script never sees it.

The reference site, installed and started as the site's user:

```bash
sudo install -d -o root -g root -m 0755 /opt/mldsa-site/examples /opt/mldsa-site/module
sudo cp -r web /opt/mldsa-site/web
sudo cp -r examples/site-node /opt/mldsa-site/examples/site-node
sudo cp build-wasm/web/mldsa_client.mjs build-wasm/web/mldsa_client.wasm /opt/mldsa-site/module/
head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' | sudo install -o www-data -m 0600 /dev/stdin /etc/mldsa-authd/invite
sudo -u www-data node /opt/mldsa-site/examples/site-node/server.mjs \
     --authd-site /run/mldsa-authd/site.sock \
     --authd-ws-unix /run/mldsa-authd/p.sock \
     --server-id authd --server-pub /var/lib/mldsa-authd/server.pub \
     --module-dir /opt/mldsa-site/module \
     --invite-file /etc/mldsa-authd/invite --port 9080 --secure
```

It prints `{"port":9080}`. Run it under your process manager. Keep the layout:
the server finds `web/` two directories above itself, as it does in the
repository.

- **`--secure` is not optional behind TLS.** The browser sends
  `Origin: https://…`, and without the flag the site expects `http://` and
  refuses every POST as cross-origin — sign-up, login, everything — while
  the pages still load.
- **The invite is the reference site's stand-in for your account check.**
  Whoever holds it can create an account; a real site uses what it already
  trusts, such as a verified e-mail. It is read from a file because argv is
  visible to every process on the host.
- `site_uids` in `authd.conf` must be this process's uid (step 7).

`deploy/Caddyfile.example` already routes `/authd/v1` to the daemon and
everything else to `127.0.0.1:9080`, under the Content-Security-Policy the
pages need. Keep `'wasm-unsafe-eval'` — the module cannot compile without it —
and add nothing looser: there is no inline script anywhere. So
`--authd-ws-unix` is never used behind Caddy; it is there for running the
site without a proxy.

## 15. The journal

For public users a device handle, a user id (often an e-mail address) and a
client address are personal data, and the journal is usually kept longer and
read more widely than the store. `authd.conf.example` sets:

```
log_identities = hashed
log_client_ip  = prefix
```

| Setting | The journal carries |
|---|---|
| `log_identities = full` | `id=alice@example.org` |
| `log_identities = hashed` | `idh=3f09c2d18a7be641` — a keyed pseudonym, stable across restarts |
| `log_identities = off` | nothing |
| `log_client_ip = full` | `src=203.0.113.77` |
| `log_client_ip = prefix` | `src=203.0.113.0/24` (IPv6: `/48`) |
| `log_client_ip = off` | nothing |

`--check-config` prints both (step 7). To find one person's lines, compute
their pseudonym — it needs the server passphrase, which is exactly who should
be able to:

```bash
sudo -u mldsa-authd authd_admin pseudonym \
     --store /var/lib/mldsa-authd/store.sqlite3 \
     --key /var/lib/mldsa-authd/server.ek \
     --passphrase-file /run/credentials/mldsa-authd.service/passphrase \
     --server-id authd --id alice@example.org
journalctl -u mldsa-authd | grep -F 'idh=3f09c2d18a7be641'
```

The first command prints `idh=…`; grep for it. Nothing is lost by hashing:
the store's audit chain (step 12) records the real identifiers under every
setting, and the rate limiter keys on the full address in memory.

## 16. Rate limits for phones

Phones share addresses: a carrier-grade NAT puts thousands of people behind
one IPv4 address. Every connection pays one token from its address's bucket
(`rate_per_min`, `rate_burst`), and **a login that authenticates gets its
token back**, so people logging in do not spend each other's budget — only
handshakes that fail do.

What it cannot fix: **one prober behind a shared address can empty it, and
everyone behind that address is refused until it refills** (spec §18). Watch
for it:

```bash
journalctl -u mldsa-authd | grep -c 'event=refused-rate-limited'
```

A steady trickle is probers being priced; a burst of them from one `src`
prefix during your busy hours is neighbours being locked out. Raising
`rate_burst` (say to 30) widens what one address may fail before it is
refused; `rate_global_per_sec` still bounds the daemon's total signing work.

## 17. Tell people what the browser cannot do

The enrollment page says these itself; your help page should too.

- **Save the recovery codes.** The account page issues five, shown once. A
  browser may **evict** its storage — clearing site data, a private window, a
  phone short of space — and with it the only copy of the key. Recovery codes
  are the way back (spec §10.3).
- **The passphrase policy refuses the obviously weak; it does not certify
  strength.** A copied key blob can be guessed offline, and Argon2id only sets
  the price per guess.
- **Script injected into your site can use an unlocked key.** No origin-level
  bug is survivable; keep the CSP exactly as it is.
- A copied blob is an undetectable clone, and there is no hardware backing.

## 18. Check it from a phone

Enroll and log in once from a real phone over mobile data, not Wi-Fi, so the
connection comes through a carrier's address. Then check the journal shows
`event=login-code-issued` with an `idh=` and a `/24`, and no plain `id=` or
full address.

**Phones have not been measured yet.** Spec §14's criteria are 50 ms of login
cryptography and 2 s of Argon2id; the only in-browser figures so far are from
headless Chromium (Edge 154) on the development Mac: a new identity (keygen +
Argon2id 3/64 MiB + sealing) in 89–106 ms, a whole login in 85–153 ms. A phone
will be several times slower, and a low-memory one may struggle with Argon2id's
64 MiB. To measure yours, on the build host (not the production daemon):

```bash
node tools/phone_timing.mjs --fixture build/tests/authd_wasm_fixture \
     --module-dir build-wasm/web --host <an address your phone reaches>
```

It prints a URL; open it on the phone and tap Measure. The page makes a
throwaway identity, logs in five times and reports the times back.

---

## When it will not start

The daemon's exit code says which half is wrong (spec §13):

| Exit | Meaning | Look at |
|---|---|---|
| 3 | configuration | the message names the key and line; `--check-config` says the same thing without starting |
| 1 | operation failed | the key would not open, or the store would not — check the credential and the file modes |
| 2 | usage | the unit's `ExecStart` |

Common ones, and what they actually are:

- **`passphrase file …: permissions`** — the credential must be a regular file,
  mode 0600 or tighter, owned by the service user. A `LoadCredentialEncrypted`
  credential is 0400 and owned correctly; a file you copied by hand may not be.
- **`unix listener …: path`** — a socket path longer than `sun_path` (104–108
  bytes). `--check-config` catches this before systemd does.
- **`its directory does not exist`** — the daemon creates sockets and the
  store, never directories. Step 4 is the one that was skipped.
- **Everything starts, no client can connect** — check `proxy_protocol` in
  `--check-config` output and the proxy's uid in `proxy_uids`.

## What this deployment does not do

- No HSM or TPM key custody: root on this host can read the server key from
  memory. `systemd-creds` protects it at rest, not at runtime.
- One host. No replication, no failover; the store is a single SQLite file.
- The head MAC is not published anywhere automatically (spec §18) — step 12 is
  manual, and a timer is your job.
- Server identity-key rotation is not specified: changing it means
  redistributing `server.pub` to every client.
