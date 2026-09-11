# mldsa-auth

ML-DSA-65 mutual-authentication handshake + X25519/HKDF/ChaCha20-Poly1305
encrypted session protocol. See
[docs/ml-dsa-auth-protocol-spec.md](docs/ml-dsa-auth-protocol-spec.md)
for the full engineering spec — the canonical, versioned copy lives in this
repository, alongside the implementation it specifies.

Status: **Step 6 (Reference TCP client/server) complete** — wire format
(Step 3), handshake state machine (Step 4), authenticated ChaCha20-Poly1305
record layer (Step 5), and a loopback reference transport with demo
client/server apps (Step 6). Full build instructions, exact dependency
versions, and the protocol's security scope will be filled in at Step 9
per the spec. See [docs/decisions.md](docs/decisions.md) for the protocol
decisions made through Step 6.

## Demo (reference apps, loopback only)

> **DEMO ONLY.** The key files below are an unencrypted demo format
> protected only by file permissions — not production key management. The
> server listens on `127.0.0.1` only. Keep generated keys in the
> git-ignored `demo-data/` directory and never commit them.

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
