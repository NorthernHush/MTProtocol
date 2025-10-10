#ifndef MESHRATCHET_AUTH_H
#define MESHRATCHET_AUTH_H

#include "../include/meshratchet.h"

typedef enum {
    MR_AUTH_NONE = 0,
    MR_AUTH_HMAC_SHA256 = 1,
    MR_AUTH_POLY1305 = 2,
    MR_AUTH_AES_GMAC = 3
} mr_auth_type_t;

typedef struct {
    mr_auth_type_t auth_type;
    uint8_t auth_key[MR_CHAIN_KEY_LEN];
    size_t tag_length;
} mr_auth_ctx_t;

int mr_auth_init(mr_auth_ctx_t* ctx, mr_auth_type_t auth_type, const uint8_t* key);
int mr_auth_generate_tag(mr_auth_ctx_t* ctx, const uint8_t* message, size_t message_len, uint8_t* auth_tag, size_t tag_len);
int mr_auth_verify_tag(mr_auth_ctx_t* ctx, const uint8_t* message, size_t message_len, const uint8_t* auth_tag, size_t tag_len);
int mr_generate_auth_keys(mr_session_t* session, const uint8_t* root_key);

#endif