#include "auth.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <string.h>

int mr_auth_init(mr_auth_ctx_t* ctx, mr_auth_type_t auth_type, const uint8_t* key) {
    if (!ctx || !key) return MR_ERROR_INVALID_PARAM;
    
    ctx->auth_type = auth_type;
    memcpy(ctx->auth_key, key, MR_CHAIN_KEY_LEN);
    
    switch (auth_type) {
        case MR_AUTH_HMAC_SHA256:
            ctx->tag_length = 32; // SHA-256
            break;
        case MR_AUTH_POLY1305:
            ctx->tag_length = 16;
            break;
        case MR_AUTH_AES_GMAC:
            ctx->tag_length = 16;
            break;
        default:
            ctx->tag_length = 16;
    }
    
    return MR_SUCCESS;
}

int mr_auth_generate_tag(mr_auth_ctx_t* ctx, const uint8_t* message, size_t message_len, 
                        uint8_t* auth_tag, size_t tag_len) {
    if (!ctx || !message || !auth_tag || tag_len < ctx->tag_length) {
        return MR_ERROR_INVALID_PARAM;
    }
    
    switch (ctx->auth_type) {
        case MR_AUTH_HMAC_SHA256: {
            unsigned int len = 0;
            HMAC(EVP_sha256(), ctx->auth_key, MR_CHAIN_KEY_LEN,
                 message, message_len, auth_tag, &len);
            if (len != ctx->tag_length) return MR_ERROR_CRYPTO;
            break;
        }
        
        case MR_AUTH_POLY1305:
            HMAC(EVP_sha256(), ctx->auth_key, MR_CHAIN_KEY_LEN,
                 message, message_len, auth_tag, NULL);
            break;
            
        default:
            return MR_ERROR_CRYPTO;
    }
    
    return MR_SUCCESS;
}

int mr_auth_verify_tag(mr_auth_ctx_t* ctx, const uint8_t* message, size_t message_len,
                      const uint8_t* auth_tag, size_t tag_len) {
    if (!ctx || !message || !auth_tag) {
        return MR_ERROR_INVALID_PARAM;
    }
    
    uint8_t computed_tag[32];
    if (mr_auth_generate_tag(ctx, message, message_len, computed_tag, sizeof(computed_tag)) != MR_SUCCESS) {
        return MR_ERROR_CRYPTO;
    }
    int result = 0;
    for (size_t i = 0; i < ctx->tag_length && i < tag_len; i++) {
        result |= (computed_tag[i] ^ auth_tag[i]);
    }
    
    if (result != 0) {
        return MR_ERROR_VERIFICATION;
    }
    
    return MR_SUCCESS;
}