/**
 * Falcon-1024 WASM wrapper for Algorand (deterministic mode).
 *
 * Uses the EXACT same deterministic Falcon API as Algorand's AVM falcon_verify.
 */

#include "falcon.h"
#include "deterministic.h"
#include <string.h>
#include <stdlib.h>

#define PK_SIZE  FALCON_DET1024_PUBKEY_SIZE
#define SK_SIZE  FALCON_DET1024_PRIVKEY_SIZE
#define SIG_MAX  FALCON_DET1024_SIG_COMPRESSED_MAXSIZE

int falcon_wasm_pk_size(void)      { return PK_SIZE; }
int falcon_wasm_sk_size(void)      { return SK_SIZE; }
int falcon_wasm_sig_maxsize(void)  { return SIG_MAX; }

/**
 * Generate a Falcon-1024 keypair from a 48-byte seed (deterministic).
 */
int falcon_wasm_keygen(
    const unsigned char *seed48,
    unsigned char *pk_out,
    unsigned char *sk_out
) {
    shake256_context rng;
    shake256_init_prng_from_seed(&rng, seed48, 48);
    return falcon_det1024_keygen(&rng, sk_out, pk_out);
}

/**
 * Deterministic compressed signature (matches Algorand's falcon_verify).
 */
int falcon_wasm_sign(
    const unsigned char *sk,
    const unsigned char *msg, int msg_len,
    unsigned char *sig_out, int *sig_len_out
) {
    size_t sig_len = SIG_MAX;
    int rc = falcon_det1024_sign_compressed(sig_out, &sig_len, sk, msg, (size_t)msg_len);
    if (rc == 0) *sig_len_out = (int)sig_len;
    return rc;
}

/**
 * Verify a deterministic compressed signature.
 */
int falcon_wasm_verify(
    const unsigned char *pk,
    const unsigned char *msg, int msg_len,
    const unsigned char *sig, int sig_len
) {
    return falcon_det1024_verify_compressed(sig, (size_t)sig_len, pk, msg, (size_t)msg_len);
}
