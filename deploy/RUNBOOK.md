# Deploying mldsa-authd

**Part I (steps 1–12), milestone A:** operators log in with `authd_client`
through an SSH tunnel. One host, systemd, root available for the install.
**Part II (steps 13–18), milestone B:** the same daemon opened to the public —
people enrolling and logging in from a browser, phones included, through your
site behind the TLS proxy. Do Part I first; Part II only adds to it.

**This runbook is rehearsed on every push.** CI's `rehearse` job takes a fresh
Ubuntu 26.04 host with systemd, runs every command block in steps 1–16 below
**as written** (`tools/rehearse_runbook.py`), and checks what each step says it
prints: a real operator login, a verified audit chain, the site's code
exchange reaching the daemon, and a journal with no plain identifier or
address in it. Where a step cannot be run literally — an editor, a
placeholder, the laptop end of a tunnel — the substitution is declared in that
tool with its reason, and CI fails if the runbook's text drifts from under it.
Its first run, in V4-99, found seven defects that stopped a deployment cold;
before then each piece had been checked on its own and the whole never had.
**What has not been checked is your machine**, nor steps 17 and 18 (another
host, a phone). Each step says what it should print, so you can tell a success
from a silence.

---

## 0. What you need

- A Linux host with systemd ≥ 250 (`systemd-analyze --version`) and root.
- A TLS proxy. Caddy is what `deploy/Caddyfile.example` is written and tested
  for; anything that speaks **PROXY protocol v2 to a Unix upstream** works.
  **Caddy 2.7 or later**: `proxy_protocol` in an upstream transport is new in
  2.7. A distribution's own package can be older — Ubuntu 26.04 ships 2.6.2,
  whose `caddy validate` refuses this Caddyfile with `unrecognized
  subdirective proxy_protocol` (V4-99) — so install from Caddy's own apt
  repository (caddyserver.com/docs/install), which also creates the `caddy`
  user and unit the steps below assume. CI tests 2.10.2.
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
`/usr/local/bin/`, and the unit, the audit unit and its timer (step 12), and the
config and Caddyfile examples into `/usr/local/share/mldsa-authd/`.

## 4. The service user and its directories

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin mldsa-authd
sudo install -d -o mldsa-authd -g mldsa-authd -m 0700 /var/lib/mldsa-authd
sudo install -d -o mldsa-authd -g mldsa-authd -m 0700 /var/lib/mldsa-authd/backups
sudo install -d -o root -g mldsa-authd -m 0750 /etc/mldsa-authd
```

`/etc/mldsa-authd` is group `mldsa-authd` because the daemon runs as that user
and must read its configuration there (step 7); a 0700 root directory stops it
at start with `authd.conf: io (Permission denied)` (V4-99). Nobody else needs in: the credential in
it is read by systemd, as root.

`/run/mldsa-authd/` is **not** created here: systemd's `RuntimeDirectory=`
makes it at start and removes it at stop, so a crash never leaves a stale
directory with the wrong mode.

Add the proxy's user to the daemon's group so it can reach the 0660 socket
(Caddy usually runs as `caddy`), and, for Part II, the site's user so it can
reach `site.sock` (the reference site runs as `www-data`):

```bash
sudo usermod -aG mldsa-authd caddy
sudo usermod -aG mldsa-authd www-data
```

The group lets them reach the sockets in `/run/mldsa-authd/` (0750); each
socket still checks the peer's uid against its own allowlist. A running process
keeps the groups it started with, so a proxy that is already running must be
**restarted**, not reloaded, before it can use this (step 10).

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

`init` refuses to run if a key (`server.ek` or `server.pub`), store or
passphrase file already exists, names which, and writes nothing. That is deliberate: re-running it against an existing store would
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
sudo install -o mldsa-authd -g mldsa-authd -m 0600 \
     /usr/local/share/mldsa-authd/authd.conf.example /etc/mldsa-authd/authd.conf
sudo -e /etc/mldsa-authd/authd.conf      # set site_uids and proxy_uids
```

The file is the service user's, mode 0600, because the daemon reads it as that
user. It cannot change it: the unit's `ProtectSystem=strict` makes `/etc`
read-only to the service.

**`--check-config` runs at every start, not here.** It checks that the key,
its passphrase and the socket directories exist, and two of those — the
credential in `/run/credentials/mldsa-authd.service/` and `/run/mldsa-authd/`
itself — exist only while systemd is starting the service. Run by hand at this
point it can only fail (`key_passphrase_file … does not exist`, exit 3;
V4-99). So the unit runs it as `ExecStartPre=`, where they do exist, and a
configuration it refuses stops the start with the reason in the journal.
Step 9 reads what it resolved.

`site_uids` must be the uid your site process runs as: `id -u www-data`.
`proxy_uids` must be the proxy's: `id -u caddy`.

The same line ends with `log_identities=` and `log_client_ip=`. The example sets
`hashed` and `prefix`, which is what Part II wants; an operators-only deployment
may prefer `full` for both, and nothing else changes (step 15 says what each
setting writes).

**The daemon reads this file once, at start.** There is no reload:
`systemctl reload mldsa-authd` is refused by systemd (the unit defines none),
and a `SIGHUP` sent by hand is logged as `warn event=sighup-ignored` and
changes nothing. `sudo systemctl restart mldsa-authd` applies a change
(step 22 does one).

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

The unit is `Type=notify`: `systemctl` returns once the daemon says it is
ready — key unsealed, every listener bound — not when the process starts.
First in the journal is `--check-config`'s line of resolved settings
(step 7). **Read its `proxy_protocol=` field.** If it says `none`, your
proxy-facing listener has no client address and the rate limiter is off — which
is a passing check and a broken deployment (audit finding F63). Then you want
`event=started`, one `event=listening-*` per configured listener, and
`event=memlock-limit`. **If `memlock-limit` is at `warn`**, the limit is below
the requirement and the daemon's secrets can be swapped to disk — fix
`LimitMEMLOCK` and restart. Nothing else reports this: libsodium hands back
unlocked memory without an error.

`event=fd-limit` is the same check for open files: the daemon needs
`max_slots + max_local_slots + 32` of them and raises its own soft limit to
that, so with systemd's defaults the line is at `info` whatever `max_slots`
is. **At `warn`** the hard limit is below the `need=` it prints, and standard
error says so with the numbers: set `LimitNOFILE=` in the unit to at least
that and restart. Until then the daemon holds fewer connections than
`max_slots` (the same line on standard error says how many) and refuses the
rest with `accept-refused-no-slot`; `authd_admin` keeps working.

**`event=store-created` must not be there.** Step 5's `init` made the store,
so a daemon that says it created one — the journal also has
`created a new, empty store (no store was there)` with the path — found
nothing at `store_path` and is serving an empty store beside your real one:
every login will be refused as an unknown user. Stop it, correct `store_path`,
delete the empty file it made (and its `-wal` and `-shm`), and start again.
The same line after any later restart means the same thing.

## 10. The proxy

```bash
sudo cp /usr/local/share/mldsa-authd/Caddyfile.example /etc/caddy/Caddyfile
sudo -e /etc/caddy/Caddyfile          # set your real hostname
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl restart caddy
```

`restart`, not `reload`: a reload keeps the process, and with it the groups it
started with, so Caddy would not yet be in `mldsa-authd` (step 4) and could
not reach the socket.

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
sudo authd_admin enroll-operator \
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
sudo authd_admin backup \
     --socket /run/mldsa-authd/admin.sock \
     --path /var/lib/mldsa-authd/backups/$(date +%F).sqlite3
```

`admin.sock` answers root only (`admin_uids = 0`, spec §16), so these are
plain `sudo`; as any other user the daemon closes the connection at accept and
the tool says `io-error` and that the daemon closed without answering, which
it does to a uid outside the socket's allowlist (V4-99, V4-101). `--path` must be absolute: the daemon
resolves it, not your shell, and writes it into `backups/` (step 4) as the
service user. The backup is 0600, like the store.

Verify the audit chain — on the live store or on any backup, with the daemon
running or stopped. The tool waits up to 5 s if the daemon is writing at that
moment. It opens only a store that exists: a mistyped `--store` fails as `io`
and creates nothing. A backup must sit in a directory the service user can
write to (`backups/` is one), because SQLite keeps its `-wal` and `-shm`
files beside the store; on read-only media it fails as `database-error`:

```bash
sudo systemd-run --quiet --wait --pipe --collect -p User=mldsa-authd \
     -p LoadCredentialEncrypted=passphrase:/etc/mldsa-authd/passphrase.cred \
     sh -c 'exec authd_admin audit-verify \
     --store /var/lib/mldsa-authd/store.sqlite3 \
     --key /var/lib/mldsa-authd/server.ek \
     --passphrase-file "$CREDENTIALS_DIRECTORY/passphrase" \
     --server-id authd'
```

The passphrase exists only as the encrypted credential (step 6), so the tool
runs the way the daemon does: as the service user, with systemd decrypting the
credential for it into `$CREDENTIALS_DIRECTORY`. The `sh -c` is what expands
that name: systemd's own `%d` is expanded only in unit files, and passed to
`systemd-run` it reaches the tool literally (V4-99).
Pointed at the daemon's own `/run/credentials/mldsa-authd.service/passphrase`
it is refused (`not-owned-by-this-user`), because outside the service that file
is not a credential delivered to it; and with the daemon stopped the file is
not there at all (V4-99).

It prints the head MAC and an entry count. **Record the head MAC somewhere off
this host** — the chain detects tampering, but only if you have something to
compare against; that is the "second trust domain" spec §9.2 asks for.

Its exit code separates the two ways it can fail (since V4-112): **1** means
the store was read and the chain did not verify, or the store could not be
opened — treat it as an incident; **3** means the key or the passphrase file
it was given could not be used (missing, wrong modes, wrong passphrase), so
nothing was verified — fix the command and run it again.

The install ships a timer that does this every hour (V4-102). Install it, run
it once now, and read what it wrote:

```bash
sudo cp /usr/local/share/mldsa-authd/mldsa-authd-audit.service \
        /usr/local/share/mldsa-authd/mldsa-authd-audit.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemd-analyze verify /etc/systemd/system/mldsa-authd-audit.service \
     /etc/systemd/system/mldsa-authd-audit.timer
sudo systemctl enable --now mldsa-authd-audit.timer
sudo systemctl start mldsa-authd-audit.service
journalctl -u mldsa-authd-audit -n 5 --no-pager
```

The journal shows `head=…` and `the audit chain verifies (N entries)`. A chain
that does not verify fails the unit, and `systemctl --failed` lists it.
Forwarding those lines off the host — your log shipper, or a mail on failure —
is what turns them into the second trust domain; the timer only guarantees
there is a line to forward. If your `server_id` is not `authd`, edit
`--server-id` in the audit unit to match.

**Restoring.** Stop the service, remove the store's write-ahead log, put the
backup in place, start it, then run `audit-verify` (above) before you trust it:

```bash
BACKUP=/var/lib/mldsa-authd/backups/YYYY-MM-DD.sqlite3    # the one to restore
sudo systemctl stop mldsa-authd
sudo rm -f /var/lib/mldsa-authd/store.sqlite3-wal /var/lib/mldsa-authd/store.sqlite3-shm
sudo install -o mldsa-authd -g mldsa-authd -m 0600 "$BACKUP" /var/lib/mldsa-authd/store.sqlite3
sudo systemctl start mldsa-authd
```

**The `rm` is the restore.** The store runs in SQLite's WAL mode, and after a
crash — the usual reason to restore — the last transactions are in
`store.sqlite3-wal`, not in `store.sqlite3`. Left beside a restored file, that
log is replayed into it when the daemon opens it, so the "restored" store comes
back with everything since the backup: rehearsed (V4-100, F188), a user
enrolled after the backup was still there after a restore that only replaced
the file. If you are restoring to undo something — a device you did not
enrol — that is exactly what would survive.

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

`ctest` must report all 3 passed — `100% tests passed out of 3`, which older
CMake (Ubuntu 24.04's 3.28) writes as `100% tests passed, 0 tests failed out of
3` (V4-103): the two known-answer tests
and the module gates (its exact export list, and no filesystem or dynamic
code). The result is `build-wasm/web/mldsa_client.{mjs,wasm}`, about 300 KB together (V4-13d: 288,109 + 13,169 bytes).

## 14. The site

The page runs the client; **your site** decides who may have an account and
turns a login code into a session. `examples/site-node/server.mjs` is a
complete reference — `node:http`, no dependencies — and it is what the tests
drive in a real browser. Use it, or hold your own site to the same seven rules:

1. **A fresh `state` per login**, kept in the visitor's server-side session and
   put in the WebSocket URL; `EXCHANGE` must present it (spec §7.1, Req 5), so a
   code cannot be replayed into someone else's session.
2. **The login code arrives in a POST body on your own origin** — never in a
   URL, so never in a proxy log, a `Referer` or history (spec §14).
3. **Every POST must carry your `Origin`**, on a session cookie that is
   `HttpOnly; SameSite=Strict; Secure` and named with the `__Host-` prefix, so
   that no other host under your domain can set it.
4. **The token stays on the server.** Page script never sees it.
5. **A new session id at every change of privilege:** a login, a signup, a
   recovery. Drop the old id with everything it held (session fixation, audit
   F131).
6. **A bounded session table.** Expire idle sessions, remove a session at
   logout, and cap the sessions nobody has logged into, evicting the least
   recently used (audit F132).
7. **New recovery codes need a login, not only a session.** Have the page log
   in again (device key and passphrase) and send that login's code; mint the
   codes only if `EXCHANGE` says it is the session's own user (V4-62).

The reference site, installed and started as the site's user:

```bash
sudo install -d -o root -g root -m 0755 /opt/mldsa-site/examples /opt/mldsa-site/module
sudo cp -r web /opt/mldsa-site/web
sudo cp -r examples/site-node /opt/mldsa-site/examples/site-node
sudo cp build-wasm/web/mldsa_client.mjs build-wasm/web/mldsa_client.wasm /opt/mldsa-site/module/
sudo install -o root -g root -m 0644 /var/lib/mldsa-authd/server.pub /opt/mldsa-site/server.pub
sudo install -d -o www-data -g www-data -m 0700 /etc/mldsa-site
head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' | sudo install -o www-data -m 0600 /dev/stdin /etc/mldsa-site/invite
sudo -u www-data node /opt/mldsa-site/examples/site-node/server.mjs \
     --authd-site /run/mldsa-authd/site.sock \
     --authd-ws-unix /run/mldsa-authd/p.sock \
     --server-id authd --server-pub /opt/mldsa-site/server.pub \
     --module-dir /opt/mldsa-site/module \
     --invite-file /etc/mldsa-site/invite --port 9080 --secure --trust-proxy
```

The site gets its own copy of `server.pub` and its own directory for the
invite because the daemon's are closed to it: `/var/lib/mldsa-authd/` is 0700
and `/etc/mldsa-authd/` admits only the daemon's group. Pointed at the
daemon's copy, the site stops at start with `EACCES … server.pub` (V4-99).
`server.pub` is public — every client pins it — so a world-readable copy is
fine; the invite is a secret, so its directory is the site user's alone.

It prints `{"port":9080}`. Run it under your process manager. Keep the layout:
the server finds `web/` two directories above itself, as it does in the
repository.

- **`--secure` is not optional behind TLS.** The browser sends
  `Origin: https://…`, and without the flag the site expects `http://` and
  refuses every POST as cross-origin — sign-up, login, everything — while
  the pages still load.
- **`--trust-proxy` belongs behind Caddy and nowhere else.** The recovery
  route is rate-limited per client, keyed on the RIGHTMOST `X-Forwarded-For`
  entry, the one the proxy added; everything to its left is the client's
  (F159). Without a proxy in front even that entry is the client's, so
  leave the flag off and the key is the TCP peer.
  It also tells the site that the proxy has already matched its name: without
  it the site serves only an IP address or `localhost` as the `Host`, and
  answers 421 to `authd.example.com` (V4-88, F177, against DNS rebinding).
- **The invite is the reference site's stand-in for your account check.**
  Whoever holds it can create an account, but not join an existing one: a
  signup enrolls `via=signup`, which the daemon refuses for a known user
  (F145). A real site uses what it already trusts, such as a verified
  e-mail. It is read from a file because argv is
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

`--check-config` prints both (step 9). To find one person's lines, compute
their pseudonym — it needs the server passphrase, which is exactly who should
be able to:

```bash
sudo systemd-run --quiet --wait --pipe --collect -p User=mldsa-authd \
     -p LoadCredentialEncrypted=passphrase:/etc/mldsa-authd/passphrase.cred \
     sh -c 'exec authd_admin pseudonym \
     --store /var/lib/mldsa-authd/store.sqlite3 \
     --key /var/lib/mldsa-authd/server.ek \
     --passphrase-file "$CREDENTIALS_DIRECTORY/passphrase" \
     --server-id authd --id alice@example.org'
journalctl -u mldsa-authd | grep -F 'idh=3f09c2d18a7be641'
```

The first command prints `idh=…` (run as step 12's `audit-verify` is, for the
same reason); grep for it. Nothing is lost by hashing:
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
- **A browser trusts your TLS for the page itself** (F137). The page's code
  arrives over it on every visit, so whoever controls your certificate or your
  proxy controls what runs where the key is unlocked. The CLI does not depend
  on it. Keep the Caddyfile's HSTS header, publish a CAA record naming your
  certificate authority, and watch certificate-transparency logs for your
  name. Check that the TLS key exchange is post-quantum, because recovery
  codes cross it, shown once and typed at recovery:

  ```bash
  openssl s_client -connect authd.example.com:443 -groups X25519MLKEM768 </dev/null 2>&1 | grep "Negotiated TLS1.3 group"
  ```

  It prints `Negotiated TLS1.3 group: X25519MLKEM768` when the server offers
  it. Offered only that group, a server without it fails the handshake, and
  the line reads `<NULL>`. That needs OpenSSL 3.5 or later (checked with
  3.6.4 against hosts of both kinds). A browser shows the key exchange in its developer tools' Security
  panel.

## 18. Check it from a phone

Enroll and log in once from a real phone over mobile data, not Wi-Fi, so the
connection comes through a carrier's address. Then check the journal shows
`event=login-code-issued` with an `idh=` and a `/24`, and no plain `id=` or
full address.

**What a phone costs, measured** (V4-25; the rows are in
`bench/results.md`). Spec §14's criteria are 50 ms of login cryptography and
2 s of Argon2id. A Xiaomi 12 Pro in Chrome and Edge made a new identity
(keygen + Argon2id 3/64 MiB + sealing) in 255–393 ms, and logged in in
301–719 ms over Wi-Fi and 512–645 ms over mobile data. Edge on the development
Mac: 109 ms and 104–110 ms. Safari on the same Mac: 94 ms and 85–100 ms on a
secure origin (V4-26).

**Safari needs a secure origin** (audit F119). Safari runs a page from plain
http on any name but `localhost` without its JIT, and is then 8–30× slower:
2.1–2.3 s for each of the above. Your site is HTTPS, so its pages are a
secure context. Every iPhone browser is WebKit and none has been measured, so
try an iPhone before relying on it. A low-memory phone may still struggle with
Argon2id's 64 MiB.

To measure your own devices, on the build host (not the production daemon):

```bash
node tools/phone_timing.mjs --fixture build/tests/authd_wasm_fixture \
     --module-dir build-wasm/web --host <an address your phone reaches>
```

It prints a URL; open it on the phone and tap Measure. The page makes a
throwaway identity, logs in five times and reports the times back.

Each result says whether the page was a **secure context**, with the time of
a plain JavaScript loop. A phone reaches the tool over plain http, which is
not a secure context. An iPhone's WebKit may then run without its JIT, as
Safari on a Mac does, so read its row with that in mind. For a browser on the build host itself, use `--host 127.0.0.1`,
which is a secure context; `--auto` starts the page without the tap. The tool
exits 1 if no result arrived before `--minutes` ran out.

The page is served only under the name you passed as `--host`, an IP
address, or `localhost` (V4-88, F177: anything else is refused as a
DNS-rebinding page). If the phone reaches the host under another name, say
a Tailscale name for an address you passed as `--host`, add
`--host-name <that name>`.

---

# Part III — running it

What an operator does after the first day. Steps 19–23 are rehearsed like
the rest (V4-104, V4-108); each says what proves it worked.

## 19. Rotate a device key

A device replaces its own key and keeps its identity (spec §10.2). On the
laptop, through the tunnel as in step 11:

```bash
authd_client rotate --handle <handle> --key ~/.mldsa/<handle>.ek \
    --passphrase-prompt --server-id authd --server-pub ./server.pub --port 8443
authd_client login --handle <handle> --key ~/.mldsa/<handle>.ek \
    --passphrase-prompt --server-id authd --server-pub ./server.pub --port 8443
```

The login prints a code under the **new** key. The old key is now refused:
the daemon retires it when it acknowledges the rotation, so a copy of the old
`.ek` file — a backup, a stolen laptop's disk — no longer logs in. A rotation
interrupted between the two (the laptop sleeps, the tunnel drops) is finished
by the next `login` or `rotate`, which asks the daemon which key is live.

## 20. Lock a user out

A lost or stolen device, or someone who should no longer have access:

```bash
sudo authd_admin disable-user --socket /run/mldsa-authd/admin.sock \
     --user you --reason lost-laptop
```

Every device of that user stops logging in at once, their tokens are deleted,
and live connections are closed (spec §10.3). The reason is one word: values
on the admin socket are single tokens (spec §8).

## 21. Let them back in

```bash
sudo authd_admin enable-user --socket /run/mldsa-authd/admin.sock --user you
```

The user's devices log in again. If the device itself was lost, enable the
user only after they have enrolled a new device, or recovered with a recovery
code, and the lost one has been revoked: enabling a user re-enables every device they
had.

## 22. Upgrade the daemon

Build the new source as in step 1, check it as in step 2, install it as in
step 3, and restart:

```bash
cd /opt/build/mldsa-auth
git pull --ff-only
cmake --build build-release -j"$(nproc)"
tools/audit/check_hardening.sh build-release --require
sudo cmake --install build-release --prefix /usr/local --component mldsa-authd
sudo diff -u /etc/systemd/system/mldsa-authd.service \
     /usr/local/share/mldsa-authd/mldsa-authd.service && echo "the unit is unchanged"
sudo systemctl restart mldsa-authd
journalctl -u mldsa-authd -n 5 --no-pager
```

The store, the key and the configuration are untouched by an install. The
install refreshes the example unit in `/usr/local/share/mldsa-authd/` but not
the copy in `/etc/systemd/system/`: if the `diff` shows a change, read it, copy
the new unit over (keeping your own `LimitMEMLOCK`, step 8), and run
`sudo systemctl daemon-reload` before the restart. `restart` returns when the
new daemon is listening (`Type=notify`, V4-104: as `Type=simple` it returned at
fork, and a login sent straight after found nothing listening). The journal
should show `event=started` again, and an existing device logs in as before.

## 23. Change the server passphrase

`authd_admin rewrap` re-seals `server.ek` under a new passphrase. The store's
audit chain and the journal's pseudonyms are keyed from a **store root key**
sealed inside `server.ek` (spec §12, version 2 of the format, V4-108), and
`rewrap` carries that key over: after the change `audit-verify` still verifies
every entry, and a user's `idh=` is the one it was. Before V4-108 those keys
came from the passphrase itself, and a change broke both (audit finding F190).

A new passphrase the service user alone can read, and the key re-sealed under
it — into a **new file**; `server.ek` is not touched:

```bash
sudo -u mldsa-authd sh -c 'umask 077; openssl rand -base64 33 | tr -d "\n" \
     > /var/lib/mldsa-authd/pass.new'
sudo systemd-run --quiet --wait --pipe --collect -p User=mldsa-authd \
     -p LoadCredentialEncrypted=passphrase:/etc/mldsa-authd/passphrase.cred \
     sh -c 'exec authd_admin rewrap --id authd \
     --in /var/lib/mldsa-authd/server.ek \
     --out /var/lib/mldsa-authd/server.ek.new \
     --old-passphrase-file "$CREDENTIALS_DIRECTORY/passphrase" \
     --new-passphrase-file /var/lib/mldsa-authd/pass.new'
```

It prints that it wrote `server.ek.new` (`MLDSAEK1 version 2, mode 0600`) and
that the chain and the pseudonyms carry over. **Copy the new passphrase
offline now**, as in step 6: there is still no escrow.

The new credential, beside the old one, and proof that the new pair opens the
store **before** anything is swapped:

```bash
sudo systemd-creds encrypt --name=passphrase \
     /var/lib/mldsa-authd/pass.new /etc/mldsa-authd/passphrase.cred.new
sudo chmod 0600 /etc/mldsa-authd/passphrase.cred.new
sudo systemd-run --quiet --wait --pipe --collect -p User=mldsa-authd \
     -p LoadCredentialEncrypted=passphrase:/etc/mldsa-authd/passphrase.cred.new \
     sh -c 'exec authd_admin audit-verify \
     --store /var/lib/mldsa-authd/store.sqlite3 \
     --key /var/lib/mldsa-authd/server.ek.new \
     --passphrase-file "$CREDENTIALS_DIRECTORY/passphrase" \
     --server-id authd'
```

It must say `the audit chain verifies`. If it does not, stop: nothing has
changed yet, and the daemon is still running on the old key and credential.

Swap both, keeping the old pair until the new one has served a login:

```bash
sudo systemctl stop mldsa-authd
sudo mv /var/lib/mldsa-authd/server.ek /var/lib/mldsa-authd/server.ek.old
sudo mv /var/lib/mldsa-authd/server.ek.new /var/lib/mldsa-authd/server.ek
sudo mv /etc/mldsa-authd/passphrase.cred /etc/mldsa-authd/passphrase.cred.old
sudo mv /etc/mldsa-authd/passphrase.cred.new /etc/mldsa-authd/passphrase.cred
sudo systemctl start mldsa-authd
journalctl -u mldsa-authd -n 5 --no-pager
```

The journal shows `event=started`. Log in as in step 11, and run step 12's
`audit-verify` once more: it reads the swapped files now. To go back instead,
stop the daemon and move the two `.old` files back. Once a login has worked:

```bash
sudo shred -u /var/lib/mldsa-authd/pass.new /var/lib/mldsa-authd/server.ek.old \
     /etc/mldsa-authd/passphrase.cred.old
```

Three things this does not do:

- **It does not revoke a copy.** A copy of the old `server.ek` — in a backup,
  on a stolen disk — still opens under the old passphrase, and it holds the
  same server key. Changing the passphrase protects a key file nobody has
  copied; if the file and its passphrase both leaked, the server's identity
  has, and that needs a new server key, which this runbook does not cover.
  Replace your own backups of `server.ek` with the new file.
- **It does not change `server.pub`.** Clients pin the same key as before.
- **It is one-way for the binary.** The file `rewrap` writes is version 2, and
  a daemon older than V4-108 refuses it (`bad-format`). Keep `server.ek.old`
  and its credential until you are sure you will not go back to an older
  build. A key file made before V4-108 (version 1) needs nothing done to it:
  the daemon reads both, and its store keeps verifying; the first `rewrap`
  makes it version 2 with the same keys.

---

## When it will not start

The daemon's exit code says which half is wrong (spec §13):

| Exit | Meaning | Look at |
|---|---|---|
| 3 | configuration | the message names the setting and line, or the file the configuration names that cannot be used: the server key or its passphrase file, missing, with unsafe modes, malformed, or not opened by the passphrase (since V4-61, F126) — check the credential and the file modes; `--check-config` reports configuration lines without starting |
| 1 | operation failed | the store would not open, or an internal failure |
| 2 | usage | the unit's `ExecStart` |

Common ones, and what they actually are:

- **`passphrase file …: unsafe-permissions`** (before V4-61:
  `permissions (mode must be 0600)`) — the credential must be a regular file,
  mode 0600 or tighter, owned by the service user. A `LoadCredentialEncrypted`
  credential is 0400 and owned correctly; a file you copied by hand may not be.
- **`unix listener …: path`** — a socket path longer than `sun_path` (104–108
  bytes). The unit's `ExecStartPre=` check catches this before the daemon
  tries to bind it.
- **`unix listener …: in-use`** (also `site socket` and `admin socket`) —
  something is listening on that socket: the service is already running, or a
  second unit or a hand-started daemon uses the same configuration. The
  running daemon is not disturbed. A socket left behind by a killed daemon
  does not cause this; it is replaced.
- **`warn event=accept-failed`** in the journal of a running daemon — an
  `accept()` failed, which in practice means the process is out of open
  files. A daemon that knows its limit is short holds fewer connections so
  that this does not happen (step 9, `warn event=fd-limit`), so seeing it
  means the limit was reached some other way; the system-wide one is the
  first to check. Logged once per run of failures on
  a listener, not once per connection; the daemon retries every 100 ms and
  recovers by itself when connections close. While it lasts, `authd_admin`
  cannot connect either.
- **`error event=loop-failed`** as a daemon's last line but two — `poll()`
  failed, which in practice means the kernel had no memory for it. The
  daemon exits 1 and systemd starts it again after `RestartSec`; sessions
  that were open are gone and their users log in again. If it recurs, look
  at the host's memory before the daemon.
- **`its directory does not exist`** — the daemon creates sockets and the
  store, never directories. Step 4 is the one that was skipped.
- **`authd.conf: io (Permission denied)`** — the daemon cannot read its
  configuration (the parenthesis names the cause since V4-101): it runs
  as `mldsa-authd`, so the file must be that user's and `/etc/mldsa-authd`
  must admit its group (steps 4 and 7).
- **Everything starts, no client can connect** — check `proxy_protocol` in
  the `--check-config` line at the top of the journal and the proxy's uid in
  `proxy_uids`.

## What this deployment does not do

- No HSM or TPM key custody: root on this host can read the server key from
  memory. `systemd-creds` protects it at rest, not at runtime.
- One host. No replication, no failover; the store is a single SQLite file.
- The head MAC is journaled hourly by the audit timer (step 12), not sent
  anywhere: getting it off this host is your log shipping's job (spec §18).
- Server identity-key rotation is not specified: changing it means
  redistributing `server.pub` to every client. Browsers pin the key at
  enrollment and refuse another (F137), so every browser identity must be
  enrolled again.
- It does not protect browser users from whoever controls the site's TLS
  (F137, §17 above).
