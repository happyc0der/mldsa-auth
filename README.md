# mldsa-auth

ML-DSA-65 mutual-authentication handshake + X25519/HKDF/ChaCha20-Poly1305
encrypted session protocol. See
[docs/ml-dsa-auth-protocol-spec.md](docs/ml-dsa-auth-protocol-spec.md)
for the full engineering spec — the canonical, versioned copy lives in this
repository, alongside the implementation it specifies.

Status: **Step 3 (Wire format) complete.** Build instructions, demo usage,
exact dependency versions, and the protocol's security scope will be
filled in at Step 9 per the spec. See
[docs/decisions.md](docs/decisions.md) for the protocol decisions made
through Step 3 (key exchange scope, liboqs algorithm scoping, dependency
pinning, `handshake_id`, and the Step 3/Step 4 responsibility boundary).

**Build requirement:** the project path (including wherever you place
`CMAKE_BINARY_DIR`) must not contain spaces — libsodium's Autotools/libtool
build breaks on whitespace in its own path, unpatchably. See
[`cmake/Dependencies.cmake`](cmake/Dependencies.cmake) for details.
