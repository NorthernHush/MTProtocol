#ifndef MESHRATCHET_CRYPTO_H
#define MESHRATCHET_CRYPTO_H

#include "../include/meshratchet.h"
#include <stdint.h>
#include <openssl/evp.h>

typedef struct {
    EVP_CIPHER_CTX* encrypt_ctx;
    EVP_CIPHER_CTX* decrypt_ctx;
    const EVP_CIPHER* cipher;
} mr_crypto_ctx_t;

int mr_crypto_init(mr_crypto_ctx_t* ctx, mr_cipher_t algorithm);
void mr_crypto_cleanup(mr_crypto_ctx_t* ctx);

int mr_crypto_encrypt(mr_crypto_ctx_t* ctx, const uint8_t* plaintext, size_t pt_len, const uint8_t* key, const uint8_t* nonce,
                     uint8_t ciphertext, size_t* ct_len);

int mr_crypto_decrypt(mr_crypto_ctx_t* ctx, const uint8_t* ciphertext, size_t ct_len, const uint8_t* key, const uint8_t* nonce, 
                    uint8_t* plaintext, size_t* pt_len);

int mr_crypto_hkdf(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, const uint8_t *info, size_t info_len,
                  uint8_t *okm, size_t okm_len);

int mr_crypto_dh(const uint8_t* priv_key, const uint8_t* pub_key, uint8_t* chared_secret);

int mr_crypto_generate_key_pair(uint8_t* public_key, uint8_t* private_key);
int mr_crypto_generate_quantum_key_pair(uint8_t* public_key, uint8_t* private_key, size_t key_len);

#endif