# mldsa-auth

ML-DSA-65 mutual-authentication handshake + X25519/HKDF/ChaCha20-Poly1305
encrypted session protocol. See
[docs/ml-dsa-auth-protocol-spec.md](docs/ml-dsa-auth-protocol-spec.md)
for the full engineering spec — the canonical, versioned copy lives in this
repository, alongside the implementation it specifies.

Status: **Step 5 (Session layer) complete** — wire format (Step 3),
handshake state machine (Step 4), and the authenticated ChaCha20-Poly1305
record layer with rekey/expiry limits (Step 5), all in-process; no
transport yet (Step 6). Build instructions, demo usage, exact dependency
versions, and the protocol's security scope will be filled in at Step 9
per the spec. See [docs/decisions.md](docs/decisions.md) for the protocol
decisions made through Step 5.

**Build requirement:** the project path (including wherever you place
`CMAKE_BINARY_DIR`) must not contain spaces — libsodium's Autotools/libtool
build breaks on whitespace in its own path, unpatchably. See
[`cmake/Dependencies.cmake`](cmake/Dependencies.cmake) for details.
