// src/crypto/zkp.c
#include "../include/meshratchet_internal.h"
#include <sodium.h>
#include <string.h>

static int ensure_sodium_init(void) {
    if (sodium_init() == -1) return MR_ERROR_CRYPTO;
    return MR_SUCCESS;
}

int mr_zkp_prove(const uint8_t* privkey,
                 const uint8_t* pubkey,
                 const uint8_t* context, size_t context_len,
                 uint8_t R_out[32], uint8_t s_out[32]) {
    if (!privkey || !pubkey || !R_out || !s_out)
        return MR_ERROR_INVALID_PARAM;
    if (ensure_sodium_init() != MR_SUCCESS)
        return MR_ERROR_CRYPTO;

    uint8_t r[32];
    randombytes_buf(r, 32);

    if (crypto_scalarmult_base(R_out, r) != 0) {
        secure_zero(r, sizeof(r));
        return MR_ERROR_CRYPTO;
    }

    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    crypto_hash_sha256_update(&st, R_out, 32);
    crypto_hash_sha256_update(&st, pubkey, 32);
    if (context && context_len > 0)
        crypto_hash_sha256_update(&st, context, context_len);
    uint8_t c[32];
    crypto_hash_sha256_final(&st, c);
    crypto_core_ed25519_scalar_reduce(c, c);

    uint8_t ca[32];
    crypto_core_ed25519_scalar_mult(ca, privkey, c);
    crypto_core_ed25519_scalar_add(s_out, ca, r);

    secure_zero(r, sizeof(r));
    secure_zero(ca, sizeof(ca));
    return MR_SUCCESS;
}

int mr_zkp_verify(const uint8_t* pubkey,
                  const uint8_t* context, size_t context_len,
                  const uint8_t R[32], const uint8_t s[32]) {
    if (!pubkey || !R || !s)
        return MR_ERROR_INVALID_PARAM;
    if (ensure_sodium_init() != MR_SUCCESS)
        return MR_ERROR_CRYPTO;

    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    crypto_hash_sha256_update(&st, R, 32);
    crypto_hash_sha256_update(&st, pubkey, 32);
    if (context && context_len > 0)
        crypto_hash_sha256_update(&st, context, context_len);
    uint8_t c[32];
    crypto_hash_sha256_final(&st, c);
    crypto_core_ed25519_scalar_reduce(c, c);

    uint8_t sG[32];
    if (crypto_scalarmult_base(sG, s) != 0)
        return MR_ERROR_CRYPTO;

    uint8_t cA[32];
    if (crypto_scalarmult(cA, c, pubkey) != 0)
        return MR_ERROR_CRYPTO;

    uint8_t R_plus_cA[32];
    if (crypto_core_ed25519_add(R_plus_cA, R, cA) != 0)
        return MR_ERROR_CRYPTO;

    if (sodium_memcmp(sG, R_plus_cA, 32) != 0)
        return MR_ERROR_VERIFICATION;

    return MR_SUCCESS;
}