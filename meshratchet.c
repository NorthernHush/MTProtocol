#include "meshratchet.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// Внутренние структуры
struct mr_ctx {
    mr_log_cb_t log_cb;
    mr_random_cb_t random_cb;
    void* user_data;
    int ref_count;
};

struct mr_session {
    uint8_t root_key[MR_ROOT_KEY_LEN];
    uint8_t send_chain_key[MR_CHAIN_KEY_LEN];
    uint8_t recv_chain_key[MR_CHAIN_KEY_LEN];
    uint8_t send_ratchet_priv[32];
    uint8_t send_ratchet_pub[32];
    uint8_t recv_ratchet_pub[32];
    uint64_t send_sequence;
    uint64_t recv_sequence;
    uint64_t prev_send_sequence;
    uint32_t key_update_count;
    uint8_t session_id[32];
    int is_valid;
};

struct mr_key_pair {
    uint8_t public_key[32];
    uint8_t private_key[32];
    mr_ctx_t* ctx;
};

// Внутренние функции
static void secure_zero(void *p, size_t n) {
    if (p == NULL) return;
    volatile unsigned char *v = (volatile unsigned char*)p;
    while (n--) *v++ = 0;
}

static int hkdf_derive(const uint8_t *salt, size_t salt_len,
                      const uint8_t *ikm, size_t ikm_len,
                      const uint8_t *info, size_t info_len,
                      uint8_t *okm, size_t okm_len) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) return MR_ERROR_CRYPTO;

    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) return MR_ERROR_CRYPTO;

    OSSL_PARAM params[6], *p = params;
    *p++ = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    if (salt && salt_len > 0) {
        *p++ = OSSL_PARAM_construct_octet_string("salt", (void*)salt, salt_len);
    } else {
        *p++ = OSSL_PARAM_construct_octet_string("salt", (void*)"", 0);
    }
    *p++ = OSSL_PARAM_construct_octet_string("key", (void*)ikm, ikm_len);
    if (info && info_len > 0) {
        *p++ = OSSL_PARAM_construct_octet_string("info", (void*)info, info_len);
    } else {
        *p++ = OSSL_PARAM_construct_octet_string("info", (void*)"", 0);
    }
    *p = OSSL_PARAM_construct_end();

    int result = MR_SUCCESS;
    if (EVP_KDF_derive(kctx, okm, okm_len, params) != 1) {
        result = MR_ERROR_CRYPTO;
    }

    EVP_KDF_CTX_free(kctx);
    return result;
}

static void log_message(mr_ctx_t* ctx, const char* format, ...) {
    if (ctx && ctx->log_cb) {
        char buffer[512];
        va_list args;
        va_start(args, format);
        vsnprintf(buffer, sizeof(buffer), format, args);
        va_end(args);
        ctx->log_cb(buffer, ctx->user_data);
    }
}

static int generate_random(mr_ctx_t* ctx, uint8_t* buffer, size_t len) {
    if (ctx && ctx->random_cb) {
        return ctx->random_cb(buffer, len, ctx->user_data);
    } else {
        return RAND_bytes(buffer, len) == 1 ? MR_SUCCESS : MR_ERROR_CRYPTO;
    }
}

static int perform_dh(mr_ctx_t* ctx, const uint8_t* priv_key, const uint8_t* pub_key, uint8_t* shared_secret) {
    EVP_PKEY *local = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv_key, 32);
    EVP_PKEY *remote = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pub_key, 32);
    if (!local || !remote) {
        if (local) EVP_PKEY_free(local);
        if (remote) EVP_PKEY_free(remote);
        return MR_ERROR_CRYPTO;
    }

    EVP_PKEY_CTX *dh_ctx = EVP_PKEY_CTX_new(local, NULL);
    if (!dh_ctx || EVP_PKEY_derive_init(dh_ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(dh_ctx, remote) <= 0) {
        EVP_PKEY_CTX_free(dh_ctx);
        EVP_PKEY_free(local);
        EVP_PKEY_free(remote);
        return MR_ERROR_CRYPTO;
    }

    size_t secret_len = 32;
    int result = EVP_PKEY_derive(dh_ctx, shared_secret, &secret_len) == 1 ? MR_SUCCESS : MR_ERROR_CRYPTO;

    EVP_PKEY_CTX_free(dh_ctx);
    EVP_PKEY_free(local);
    EVP_PKEY_free(remote);
    return result;
}

static void ratchet_chain_key(uint8_t chain_key[MR_CHAIN_KEY_LEN], uint8_t output_key[MR_CHAIN_KEY_LEN]) {
    static const uint8_t message_label[] = "message";
    static const uint8_t ratchet_label[] = "ratchet";
    
    // output_key = HMAC(chain_key, "message")
    HMAC(EVP_sha256(), chain_key, MR_CHAIN_KEY_LEN,
         message_label, sizeof(message_label) - 1, output_key, NULL);
    
    // chain_key = HMAC(chain_key, "ratchet")  
    HMAC(EVP_sha256(), chain_key, MR_CHAIN_KEY_LEN,
         ratchet_label, sizeof(ratchet_label) - 1, chain_key, NULL);
}

static int generate_message_keys(mr_session_t* session, uint8_t* message_key, uint8_t* nonce) {
    if (!session || !message_key || !nonce) return MR_ERROR_INVALID_PARAM;
    
    ratchet_chain_key(session->send_chain_key, message_key);
    
    // Генерация nonce из sequence number
    memset(nonce, 0, MR_NONCE_LEN);
    uint64_t sequence = session->send_sequence;
    for (int i = 0; i < 8; i++) {
        nonce[MR_NONCE_LEN - 8 + i] = (sequence >> (56 - i * 8)) & 0xFF;
    }
    
    session->send_sequence++;
    return MR_SUCCESS;
}

// ===== РЕАЛИЗАЦИЯ ПУБЛИЧНЫХ ФУНКЦИЙ =====

mr_ctx_t* mr_init(void) {
    return mr_init_ex(NULL, NULL, NULL);
}

mr_ctx_t* mr_init_ex(mr_log_cb_t log_cb, mr_random_cb_t random_cb, void* user_data) {
    mr_ctx_t* ctx = calloc(1, sizeof(mr_ctx_t));
    if (!ctx) return NULL;
    
    ctx->log_cb = log_cb;
    ctx->random_cb = random_cb;
    ctx->user_data = user_data;
    ctx->ref_count = 1;
    
    return ctx;
}

void mr_cleanup(mr_ctx_t* ctx) {
    if (ctx && --ctx->ref_count <= 0) {
        secure_zero(ctx, sizeof(mr_ctx_t));
        free(ctx);
    }
}

mr_key_pair_t* mr_generate_key_pair(mr_ctx_t* ctx) {
    if (!ctx) return NULL;
    
    mr_key_pair_t* key_pair = calloc(1, sizeof(mr_key_pair_t));
    if (!key_pair) return NULL;
    
    key_pair->ctx = ctx;
    ctx->ref_count++;
    
    if (generate_random(ctx, key_pair->private_key, 32) != MR_SUCCESS) {
        free(key_pair);
        return NULL;
    }
    
    // Генерация публичного ключа из приватного
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, 
                                                 key_pair->private_key, 32);
    if (!pkey) {
        secure_zero(key_pair, sizeof(mr_key_pair_t));
        free(key_pair);
        return NULL;
    }
    
    size_t pub_len = 32;
    if (EVP_PKEY_get_raw_public_key(pkey, key_pair->public_key, &pub_len) != 1) {
        EVP_PKEY_free(pkey);
        secure_zero(key_pair, sizeof(mr_key_pair_t));
        free(key_pair);
        return NULL;
    }
    
    EVP_PKEY_free(pkey);
    return key_pair;
}

void mr_free_key_pair(mr_key_pair_t* key_pair) {
    if (key_pair) {
        secure_zero(key_pair->private_key, sizeof(key_pair->private_key));
        if (key_pair->ctx) {
            mr_cleanup(key_pair->ctx);
        }
        secure_zero(key_pair, sizeof(mr_key_pair_t));
        free(key_pair);
    }
}

int mr_export_public_key(const mr_key_pair_t* key_pair, uint8_t* buffer, size_t buffer_len) {
    if (!key_pair || !buffer || buffer_len < 32) return MR_ERROR_INVALID_PARAM;
    memcpy(buffer, key_pair->public_key, 32);
    return MR_SUCCESS;
}

int mr_session_create(mr_ctx_t* ctx, const mr_key_pair_t* local_key,
                     const uint8_t* remote_public_key, size_t pubkey_len,
                     mr_session_t** session) {
    if (!ctx || !local_key || !remote_public_key || pubkey_len != 32 || !session) {
        return MR_ERROR_INVALID_PARAM;
    }

    mr_session_t* sess = calloc(1, sizeof(mr_session_t));
    if (!sess) return MR_ERROR_MEMORY;

    // Вычисление общего секрета
    uint8_t shared_secret[32];
    if (perform_dh(ctx, local_key->private_key, remote_public_key, shared_secret) != MR_SUCCESS) {
        free(sess);
        return MR_ERROR_CRYPTO;
    }

    // Генерация корневого ключа
    if (hkdf_derive(NULL, 0, shared_secret, 32, 
                   (const uint8_t*)"MeshRatchetRoot", 15,
                   sess->root_key, MR_ROOT_KEY_LEN) != MR_SUCCESS) {
        secure_zero(sess, sizeof(mr_session_t));
        free(sess);
        secure_zero(shared_secret, sizeof(shared_secret));
        return MR_ERROR_CRYPTO;
    }

    // Инициализация цепочек
    if (hkdf_derive(sess->root_key, MR_ROOT_KEY_LEN, NULL, 0,
                   (const uint8_t*)"SendChain", 9,
                   sess->send_chain_key, MR_CHAIN_KEY_LEN) != MR_SUCCESS ||
        hkdf_derive(sess->root_key, MR_ROOT_KEY_LEN, NULL, 0,
                   (const uint8_t*)"RecvChain", 9,
                   sess->recv_chain_key, MR_CHAIN_KEY_LEN) != MR_SUCCESS) {
        secure_zero(sess, sizeof(mr_session_t));
        free(sess);
        secure_zero(shared_secret, sizeof(shared_secret));
        return MR_ERROR_CRYPTO;
    }

    // Генерация ratchet ключей
    if (generate_random(ctx, sess->send_ratchet_priv, 32) != MR_SUCCESS) {
        secure_zero(sess, sizeof(mr_session_t));
        free(sess);
        secure_zero(shared_secret, sizeof(shared_secret));
        return MR_ERROR_CRYPTO;
    }

    memcpy(sess->recv_ratchet_pub, remote_public_key, 32);
    
    // Генерация ID сессии
    if (generate_random(ctx, sess->session_id, 32) != MR_SUCCESS) {
        secure_zero(sess, sizeof(mr_session_t));
        free(sess);
        secure_zero(shared_secret, sizeof(shared_secret));
        return MR_ERROR_CRYPTO;
    }

    sess->is_valid = 1;
    *session = sess;
    
    secure_zero(shared_secret, sizeof(shared_secret));
    log_message(ctx, "Session created successfully");
    return MR_SUCCESS;
}

int mr_encrypt(mr_session_t* session, mr_msg_type_t msg_type,
               const uint8_t* plaintext, size_t pt_len,
               uint8_t* ciphertext, size_t ct_buffer_len, size_t* ct_len) {
    if (!session || !plaintext || !ciphertext || !ct_len || pt_len == 0) {
        return MR_ERROR_INVALID_PARAM;
    }

    if (pt_len > MR_MAX_MSG_SIZE) {
        return MR_ERROR_BUFFER_TOO_SMALL;
    }

    size_t required_len = 1 + 8 + MR_NONCE_LEN + pt_len + MR_TAG_LEN;
    if (ct_buffer_len < required_len) {
        return MR_ERROR_BUFFER_TOO_SMALL;
    }

    // Проверка необходимости обновления ключей
    if (session->send_sequence % MR_KEY_UPDATE_INTERVAL == 0 && session->send_sequence > 0) {
        mr_key_update(session);
    }

    // Генерация ключей сообщения
    uint8_t message_key[MR_CHAIN_KEY_LEN];
    uint8_t nonce[MR_NONCE_LEN];
    if (generate_message_keys(session, message_key, nonce) != MR_SUCCESS) {
        return MR_ERROR_CRYPTO;
    }

    // Формат сообщения: [type:1][sequence:8][nonce:12][ciphertext:var][tag:16]
    size_t offset = 0;
    ciphertext[offset++] = (uint8_t)msg_type;
    
    uint64_t sequence = session->send_sequence - 1; // Уже увеличился в generate_message_keys
    for (int i = 0; i < 8; i++) {
        ciphertext[offset++] = (sequence >> (56 - i * 8)) & 0xFF;
    }
    
    memcpy(ciphertext + offset, nonce, MR_NONCE_LEN);
    offset += MR_NONCE_LEN;

    // Шифрование
    EVP_AEAD_CTX* aead_ctx = EVP_AEAD_CTX_new(EVP_aead_chacha20_poly1305(), message_key, 32, MR_TAG_LEN);
    if (!aead_ctx) {
        secure_zero(message_key, sizeof(message_key));
        return MR_ERROR_CRYPTO;
    }

    size_t written;
    int ok = EVP_AEAD_CTX_seal(aead_ctx,
                              ciphertext + offset, &written, pt_len + MR_TAG_LEN,
                              nonce, MR_NONCE_LEN,
                              plaintext, pt_len,
                              NULL, 0);

    EVP_AEAD_CTX_free(aead_ctx);
    secure_zero(message_key, sizeof(message_key));

    if (!ok) {
        return MR_ERROR_CRYPTO;
    }

    *ct_len = offset + written;
    return MR_SUCCESS;
}

int mr_decrypt(mr_session_t* session, 
               const uint8_t* ciphertext, size_t ct_len,
               uint8_t* plaintext, size_t pt_buffer_len, size_t* pt_len,
               mr_msg_type_t* msg_type) {
    if (!session || !ciphertext || !plaintext || !pt_len || !msg_type) {
        return MR_ERROR_INVALID_PARAM;
    }

    if (ct_len < 1 + 8 + MR_NONCE_LEN + MR_TAG_LEN) {
        return MR_ERROR_INVALID_PARAM;
    }

    // Парсинг заголовка
    size_t offset = 0;
    *msg_type = (mr_msg_type_t)ciphertext[offset++];
    
    uint64_t sequence = 0;
    for (int i = 0; i < 8; i++) {
        sequence = (sequence << 8) | ciphertext[offset++];
    }

    const uint8_t* nonce = ciphertext + offset;
    offset += MR_NONCE_LEN;
    
    const uint8_t* encrypted_data = ciphertext + offset;
    size_t data_len = ct_len - offset;

    // Проверка sequence number
    if (sequence < session->recv_sequence) {
        return MR_ERROR_SEQUENCE; // Повторное сообщение
    }

    // Пропуск ключей для потерянных сообщений
    if (sequence > session->recv_sequence) {
        size_t skip_count = sequence - session->recv_sequence;
        if (skip_count > MR_MAX_SKIP_KEYS) {
            return MR_ERROR_KEY_EXHAUSTED;
        }
        for (size_t i = 0; i < skip_count; i++) {
            ratchet_chain_key(session->recv_chain_key, session->recv_chain_key);
        }
        session->recv_sequence = sequence;
    }

    // Получение ключа сообщения
    uint8_t message_key[MR_CHAIN_KEY_LEN];
    ratchet_chain_key(session->recv_chain_key, message_key);
    session->recv_sequence++;

    // Дешифрование
    EVP_AEAD_CTX* aead_ctx = EVP_AEAD_CTX_new(EVP_aead_chacha20_poly1305(), message_key, 32, MR_TAG_LEN);
    if (!aead_ctx) {
        secure_zero(message_key, sizeof(message_key));
        return MR_ERROR_CRYPTO;
    }

    size_t written;
    int ok = EVP_AEAD_CTX_open(aead_ctx,
                              plaintext, &written, pt_buffer_len,
                              nonce, MR_NONCE_LEN,
                              encrypted_data, data_len,
                              NULL, 0);

    EVP_AEAD_CTX_free(aead_ctx);
    secure_zero(message_key, sizeof(message_key));

    if (!ok) {
        return MR_ERROR_CRYPTO;
    }

    *pt_len = written;
    return MR_SUCCESS;
}

int mr_key_update(mr_session_t* session) {
    if (!session) return MR_ERROR_INVALID_PARAM;

    // Генерация новых ratchet ключей
    if (generate_random(session->ctx, session->send_ratchet_priv, 32) != MR_SUCCESS) {
        return MR_ERROR_CRYPTO;
    }

    // Вычисление нового общего секрета
    uint8_t shared_secret[32];
    if (perform_dh(session->ctx, session->send_ratchet_priv, session->recv_ratchet_pub, shared_secret) != MR_SUCCESS) {
        return MR_ERROR_CRYPTO;
    }

    // Обновление корневого ключа
    uint8_t new_root_key[MR_ROOT_KEY_LEN];
    if (hkdf_derive(session->root_key, MR_ROOT_KEY_LEN, shared_secret, 32,
                   (const uint8_t*)"KeyUpdate", 9, new_root_key, MR_ROOT_KEY_LEN) != MR_SUCCESS) {
        secure_zero(shared_secret, sizeof(shared_secret));
        return MR_ERROR_CRYPTO;
    }

    memcpy(session->root_key, new_root_key, MR_ROOT_KEY_LEN);
    
    // Сброс цепочек
    if (hkdf_derive(session->root_key, MR_ROOT_KEY_LEN, NULL, 0,
                   (const uint8_t*)"SendChain", 9, session->send_chain_key, MR_CHAIN_KEY_LEN) != MR_SUCCESS ||
        hkdf_derive(session->root_key, MR_ROOT_KEY_LEN, NULL, 0,
                   (const uint8_t*)"RecvChain", 9, session->recv_chain_key, MR_CHAIN_KEY_LEN) != MR_SUCCESS) {
        secure_zero(shared_secret, sizeof(shared_secret));
        return MR_ERROR_CRYPTO;
    }

    session->prev_send_sequence = session->send_sequence;
    session->key_update_count++;
    
    secure_zero(shared_secret, sizeof(shared_secret));
    secure_zero(new_root_key, sizeof(new_root_key));
    
    log_message(session->ctx, "Key update performed (count: %u)", session->key_update_count);
    return MR_SUCCESS;
}

void mr_session_free(mr_session_t* session) {
    if (session) {
        secure_zero(session->root_key, sizeof(session->root_key));
        secure_zero(session->send_chain_key, sizeof(session->send_chain_key));
        secure_zero(session->recv_chain_key, sizeof(session->recv_chain_key));
        secure_zero(session->send_ratchet_priv, sizeof(session->send_ratchet_priv));
        secure_zero(session, sizeof(mr_session_t));
        free(session);
    }
}

const char* mr_error_string(mr_result_t error) {
    switch (error) {
        case MR_SUCCESS: return "Success";
        case MR_ERROR_INVALID_PARAM: return "Invalid parameter";
        case MR_ERROR_MEMORY: return "Memory allocation error";
        case MR_ERROR_CRYPTO: return "Cryptographic operation failed";
        case MR_ERROR_SESSION: return "Session error";
        case MR_ERROR_SEQUENCE: return "Sequence number error";
        case MR_ERROR_VERIFICATION: return "Verification failed";
        case MR_ERROR_BUFFER_TOO_SMALL: return "Buffer too small";
        case MR_ERROR_KEY_EXHAUSTED: return "Key material exhausted";
        default: return "Unknown error";
    }
}

int mr_get_version(char* buffer, size_t buffer_len) {
    if (!buffer || buffer_len < strlen(MESHRATCHET_VERSION) + 1) {
        return MR_ERROR_BUFFER_TOO_SMALL;
    }
    strncpy(buffer, MESHRATCHET_VERSION, buffer_len);
    return MR_SUCCESS;
}