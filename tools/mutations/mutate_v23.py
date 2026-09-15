#!/usr/bin/env python3
"""V2-3 mutations (K1-K5). Each `old` must occur exactly once; every
mutation carries a MUTATION marker. Usage: mutate_v23.py <repo> <K-id>"""
import sys, pathlib
W = "src/crypto/mlkem_wrap.c"
T = "tests/test_vectors.c"
M = {
    "K1": [(W, """    const OQS_STATUS rc = OQS_KEM_encaps(kem, ct, ss, ek);
    OQS_KEM_free(kem);""",
               """    const OQS_STATUS rc = OQS_SUCCESS; /* MUTATION K1: encaps skipped, ct/ss never written */
    OQS_KEM_free(kem);""")],
    "K2": [(W, """    const OQS_STATUS rc = OQS_KEM_decaps(kem, ss, ct, kp->secret_key);
    OQS_KEM_free(kem);

    if (rc != OQS_SUCCESS) {""",
               """    const OQS_STATUS rc = OQS_KEM_decaps(kem, ss, ct, kp->secret_key);
    OQS_KEM_free(kem);

    if (0 && rc != OQS_SUCCESS) { /* MUTATION K2: decaps status ignored */""")],
    "K3": [(W, """    const OQS_STATUS rc = OQS_KEM_encaps(kem, ct, ss, ek);
    OQS_KEM_free(kem);

    if (rc != OQS_SUCCESS) {""",
               """    const OQS_STATUS rc = OQS_KEM_encaps(kem, ct, ss, ek);
    OQS_KEM_free(kem);

    if (0 && rc != OQS_SUCCESS) { /* MUTATION K3: encaps status ignored */""")],
    # K4: the encapsulation key is not cleared -- an observable named failure.
    "K4": [(W, """        kp->secret_key = NULL;
    }
    memset(kp->public_key, 0, sizeof(kp->public_key));
}""",
               """        kp->secret_key = NULL;
    }
    /* MUTATION K4: public_key left intact */
}""")],
    # K4b: the pointer is left dangling, so the idempotent free double-frees.
    # The process aborts before stdout is flushed, so this one is judged by
    # the abort itself (and by ASan's heap diagnosis), not by a printed line.
    "K4b": [(W, """        secure_mem_free(kp->secret_key, MLKEM_SECRET_KEY_BYTES);
        kp->secret_key = NULL;""",
                """        secure_mem_free(kp->secret_key, MLKEM_SECRET_KEY_BYTES);
        /* MUTATION K4b: pointer left dangling */""")],
    "K5": [(T, """    off += (size_t)snprintf(record + off, sizeof record - off, "ct = ");
    append_hex(record, sizeof record, &off, ct, MLKEM_CIPHERTEXT_BYTES);""",
               """    off += (size_t)snprintf(record + off, sizeof record - off, "ct = ");
    { /* MUTATION K5: one ct byte altered in the hashed record only */
        uint8_t ct_m[MLKEM_CIPHERTEXT_BYTES];
        memcpy(ct_m, ct, sizeof ct_m);
        ct_m[0] ^= 0x01;
        append_hex(record, sizeof record, &off, ct_m, MLKEM_CIPHERTEXT_BYTES);
    }
    if (0) append_hex(record, sizeof record, &off, ct, MLKEM_CIPHERTEXT_BYTES);""")],
}
def main():
    repo, mid = pathlib.Path(sys.argv[1]), sys.argv[2]
    texts = {}
    for path, old, new in M[mid]:
        t = texts.get(path, (repo / path).read_text())
        n = t.count(old)
        if n != 1:
            sys.exit(f"{mid}: expected exactly 1 occurrence in {path}, found {n}")
        texts[path] = t.replace(old, new, 1)
    for path, t in texts.items():
        (repo / path).write_text(t)
    print(f"{mid}: applied")
if __name__ == "__main__":
    main()
