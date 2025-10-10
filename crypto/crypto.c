#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <string.h>

int mr_crypto_init(mr_crypto_ctx_t* ctx, mr_cipher_t algorithm) {
    if(!ctx) return MR_ERROR_INVALID_PARAM;

    memset(ctx, 0, sizeof(mr_crypto_ctx_t));

    switch(algorithm) {
        case MR_CIPHER_CHACHA20:
            ctx->cipher = EVP_chacha20_poly1305();
            break;
        case MR_CIPHER_AES256_GCM:
            ctx->cipher = EVP_aes_256_gcm();
            break;
        case MR_CIPHER_AES128_GCM:
            ctx->cipher = EVP_aes_128_gcm();
            break;
        default:
            ctx->cipher = EVP_chacha20_poly1305();
    }

    ctx->encrypt_ctx = EVP_CIPHER_CTX_new();
    ctx->decrypt_ctx = EVP_CIPHER_CTX_new();

    if(!ctx->encrypt_ctx || !ctx->decrypt_ctx) {
        mr_crypto_cleanup(ctx);
        return MR_ERROR_CRYPTO;
    }

    return MR_SUCCESS;
}

void mr_crypto_cleanup(mr_crypto_ctx_t* ctx) {
    if(ctx) {
        if(ctx->encrypt_ctx) EVP_CIPHER_CTX_free(ctx->encrypt_ctx);
        if(ctx->decrypt_ctx) EVP_CIPHER_CTX_free(ctx->decrypt_ctx);
        memset(ctx, 0, sizeof(mr_crypto_ctx_t));
    }
}