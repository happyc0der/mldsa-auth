# mldsa-auth

ML-DSA-65 mutual-authentication handshake + X25519/HKDF/ChaCha20-Poly1305
encrypted session protocol. See
[docs/ml-dsa-auth-protocol-spec.md](docs/ml-dsa-auth-protocol-spec.md)
for the full engineering spec — the canonical, versioned copy lives in this
repository, alongside the implementation it specifies.

Status: **Step 8 (Benchmarking) complete** — wire
format (Step 3), handshake state machine (Step 4), authenticated
ChaCha20-Poly1305 record layer (Step 5), loopback reference transport with
demo client/server apps (Step 6), and libFuzzer targets plus a portable
deterministic fuzz smoke for every attacker-controlled input (Step 7; see
[tests/fuzz/README.md](tests/fuzz/README.md)). The Step 7 fuzz finding (the
demo key loader accepted a corrupted secret-key t0 component) is resolved
by the `MLDSASK2` integrity digest (Step 7.1; see
[docs/decisions.md](docs/decisions.md)). Measured performance is in
[bench/results.md](bench/results.md): a full mutual handshake takes
**0.372 ms** (median, in process, Apple M4 Pro) against the spec's 15 ms
target, and the record layer runs at 722 MiB/s with 64 KiB payloads. Full build
instructions, exact dependency versions, and the protocol's security scope
will be filled in at Step 9 per the spec.

## Demo (reference apps, loopback only)

> **DEMO ONLY.** The key files below are an unencrypted demo format
> protected only by file permissions — not production key management. The
> server listens on `127.0.0.1` only. Keep generated keys in the
> git-ignored `demo-data/` directory and never commit them.
>
> `keygen` writes `MLDSASK2` secret key files, which carry a SHA-256
> integrity digest checked on every load, so a corrupted or truncated key
> file is rejected. The digest is unkeyed: it detects corruption, not
> tampering. Legacy `MLDSASK1` key files are rejected; regenerate them with
> `keygen`.

```sh
# 1. Generate one identity per side (secret key file is created 0600).
./build/apps/auth_server keygen --id demo-server --dir demo-data
./build/apps/auth_client keygen --id demo-client --dir demo-data

# 2. Terminal 1: serve one connection, pinning the client's public key.
./build/apps/auth_server serve --id demo-server --key demo-data/demo-server.sk \
    --pin demo-client=demo-data/demo-client.pub --once

# 3. Terminal 2: connect, pinning the server's public key.
./build/apps/auth_client connect --id demo-client --key demo-data/demo-client.sk \
    --peer demo-server=demo-data/demo-server.pub --message "hello" --message "again"
```

Both sides authenticate each other with ML-DSA-65 against the explicitly
pinned keys. The server immediately sends an empty authenticated record, and
the client sends nothing until that record verifies. Each message comes back
as an authenticated echo, and the connection ends with an authenticated
GOODBYE. Nothing secret or decrypted is logged. Framing, limits and
timeouts: spec §6.5.

**Build requirement:** the project path (including wherever you place
`CMAKE_BINARY_DIR`) must not contain spaces — libsodium's Autotools/libtool
build breaks on whitespace in its own path, unpatchably. See
[`cmake/Dependencies.cmake`](cmake/Dependencies.cmake) for details.
