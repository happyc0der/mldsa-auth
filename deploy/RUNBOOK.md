# Deploying mldsa-authd

Milestone A: operators log in with `authd_client`, or through a browser behind
your TLS proxy. One host, systemd, root available for the install.

Everything below has been checked as far as it can be without your host: the
unit passes systemd's own analysers, the hardened binary is built and gated on
x86_64 Linux in CI, the offline build is proven with the network switched off,
and the backup/restore drill runs end to end. **What has not been checked is
your machine.** Steps 1–12 are the part only you can run; each says what it
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
tools/audit/check_backend_symbols.sh build-release
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
authd_client keygen --dir ~/.mldsa --passphrase-file ~/.mldsa/pass
```

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
    --passphrase-file ~/.mldsa/pass --server-id authd \
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
