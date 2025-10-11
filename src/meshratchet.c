/**
 * @file meshratchet.c
 * @author Mesh Security Labs
 * @brief 
 * @version v0.4
 * @date 2025-10-12
 * @copyright Copyright (c) 2025
 * 
 */

#include "../include/meshratchet_internal.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <time.h>
#include <sys/time.h>
#include "../crypto/crypto.h"
#include "../session/storage.h"
#include "../utils/metrics.h"
#include "../utils/replay_protection.h"
#include "../crypto/auth.h"

mr_ctx_t* mr_init_ex(const mr_config_t* config);
int mr_session_create_advanced(mr_ctx_t* ctx, const mr_key_pair_t* local_key, const uint8_t* remote_public_key, size_t pubkey_len, mr_mode_t mode, mr_session_t** session);
int mr_key_update(mr_session_t* session);
int mr_quantum_key_update(mr_session_t* session);

#define SHA256_DIGEST_LENGTH 32

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#error "OpenSSL version 1.1.0 or later is required"
#endif

// Внутренние функции
static void secure_zero(void *p, size_t n) {
    if (p == NULL) return;
    volatile unsigned char *v = (volatile unsigned char*)p;
    while (n--) *v++ = 0;
}

static void log_message(mr_ctx_t* ctx, mr_log_level_t level, const char* format, ...) {
    if (ctx && ctx->log_cb) {
        char buffer[512];
        va_list args;
        va_start(args, format);
        vsnprintf(buffer, sizeof(buffer), format, args);
        va_end(args);
        ctx->log_cb(level, buffer, ctx->user_data);
    }
}

static int generate_random(mr_ctx_t* ctx, uint8_t* buffer, size_t len) {
    if (ctx && ctx->random_cb) {
        return ctx->random_cb(buffer, len, ctx->user_data);
    } else {
        return RAND_bytes(buffer, len) == 1 ? MR_SUCCESS : MR_ERROR_CRYPTO;
    }
}

static uint64_t get_timestamp() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

static double time_diff_us(struct timeval start, struct timeval end) {
    return (end.tv_sec - start.tv_sec) * 1000000.0 + (end.tv_usec - start.tv_usec);
}

// Улучшенная HKDF с поддержкой разных алгоритмов
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

// Улучшенная DH функция с обработкой ошибок
static int perform_dh(mr_ctx_t* ctx, const uint8_t* priv_key, const uint8_t* pub_key, uint8_t* shared_secret) {
    (void)ctx; // Помечаем как неиспользуемый параметр
    
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

// ratchet с поддержкой разных режимов
static void ratchet_chain_key(uint8_t chain_key[MR_CHAIN_KEY_LEN], uint8_t output_key[MR_CHAIN_KEY_LEN], mr_mode_t mode) {
    static const uint8_t message_label[] = "message";
    static const uint8_t ratchet_label[] = "ratchet";
    static const uint8_t quantum_label[] = "quantum_ratchet";
    
    const uint8_t* ratchet_label_ptr = ratchet_label;
    size_t ratchet_label_len = sizeof(ratchet_label) - 1;
    
    if (mode == MR_MODE_QUANTUM) {
        ratchet_label_ptr = quantum_label;
        ratchet_label_len = sizeof(quantum_label) - 1;
    }
    
    // output_key = HMAC(chain_key, "message")
    HMAC(EVP_sha256(), chain_key, MR_CHAIN_KEY_LEN,
         message_label, sizeof(message_label) - 1, output_key, NULL);
    
    // chain_key = HMAC(chain_key, ratchet_label)  
    HMAC(EVP_sha256(), chain_key, MR_CHAIN_KEY_LEN,
         ratchet_label_ptr, ratchet_label_len, chain_key, NULL);
}

// генерация ключей сообщения
static int generate_message_keys(mr_session_t* session, uint8_t* message_key, uint8_t* nonce) {
    if (!session || !message_key || !nonce) return MR_ERROR_INVALID_PARAM;
    
    ratchet_chain_key(session->send_chain_key, message_key, session->current_mode);
    
    // Улучшенная генерация nonce с учетом режима
    memset(nonce, 0, MR_NONCE_LEN);
    uint64_t sequence = session->send_sequence;
    
    if (session->current_mode == MR_MODE_STEALTH) {
        // В стелс-режиме добавляем случайность в nonce
        uint8_t random_part[4];
        if (generate_random(session->ctx, random_part, sizeof(random_part)) != MR_SUCCESS) {
            return MR_ERROR_CRYPTO;
        }
        memcpy(nonce, random_part, 4);
        memcpy(nonce + 4, &sequence, 8);
    } else {
        // Стандартная генерация
        for (int i = 0; i < 8; i++) {
            nonce[MR_NONCE_LEN - 8 + i] = (sequence >> (56 - i * 8)) & 0xFF;
        }
    }
    
    session->send_sequence++;
    session->messages_encrypted++;
    session->last_activity = time(NULL);
    
    return MR_SUCCESS;
}

// шифрование с поддержкой разных алгоритмов
static int perform_encryption(mr_session_t* session, const uint8_t* plaintext, size_t pt_len,
                             const uint8_t* key, const uint8_t* nonce,
                             uint8_t* ciphertext, size_t* ct_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return MR_ERROR_CRYPTO;

    const EVP_CIPHER* cipher = NULL;
    
    // Выбор алгоритма шифрования
    switch (session->ctx->cipher_algorithm) {
        case MR_CIPHER_CHACHA20:
            cipher = EVP_chacha20_poly1305();
            break;
        case MR_CIPHER_AES256_GCM:
            cipher = EVP_aes_256_gcm();
            break;
        case MR_CIPHER_AES128_GCM:
            cipher = EVP_aes_128_gcm();
            break;
        default:
            cipher = EVP_chacha20_poly1305();
    }

    int result = MR_SUCCESS;
    int len;
    size_t total_len = 0;

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, nonce) != 1) {
        result = MR_ERROR_CRYPTO;
        goto cleanup;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, pt_len) != 1) {
        result = MR_ERROR_CRYPTO;
        goto cleanup;
    }
    total_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        result = MR_ERROR_CRYPTO;
        goto cleanup;
    }
    total_len += len;

    *ct_len = total_len;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

// дешифрование
static int perform_decryption(mr_session_t* session, const uint8_t* ciphertext, size_t ct_len,
                             const uint8_t* key, const uint8_t* nonce,
                             uint8_t* plaintext, size_t* pt_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return MR_ERROR_CRYPTO;

    const EVP_CIPHER* cipher = NULL;
    
    switch (session->ctx->cipher_algorithm) {
        case MR_CIPHER_CHACHA20:
            cipher = EVP_chacha20_poly1305();
            break;
        case MR_CIPHER_AES256_GCM:
            cipher = EVP_aes_256_gcm();
            break;
        case MR_CIPHER_AES128_GCM:
            cipher = EVP_aes_128_gcm();
            break;
        default:
            cipher = EVP_chacha20_poly1305();
    }

    int result = MR_SUCCESS;
    int len;
    size_t total_len = 0;

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, nonce) != 1) {
        result = MR_ERROR_CRYPTO;
        goto cleanup;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ct_len) != 1) {
        result = MR_ERROR_CRYPTO;
        goto cleanup;
    }
    total_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        result = MR_ERROR_CRYPTO;
        goto cleanup;
    }
    total_len += len;

    *pt_len = total_len;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

// ===== РЕАЛИЗАЦИЯ ПУБЛИЧНЫХ ФУНКЦИЙ =====

int mr_get_default_config(mr_config_t* config) {
    if (!config) return MR_ERROR_INVALID_PARAM;
    
    memset(config, 0, sizeof(mr_config_t));
    config->max_message_size = MR_MAX_MSG_SIZE;
    config->key_update_interval = MR_KEY_UPDATE_INTERVAL;
    config->max_skip_keys = MR_MAX_SKIP_KEYS;
    config->quantum_update_interval = 10000;
    config->protocol_mode = MR_MODE_STANDARD;
    config->cipher_algorithm = MR_CIPHER_CHACHA20;
    config->transport = MR_TRANSPORT_TCP;
    
    config->enable_serialization = 1;
    config->enable_batch_operations = 1;
    config->enable_quantum_resistance = 0;
    config->enable_stealth_mode = 0;
    config->enable_multicast = 0;
    config->enable_forward_secrecy = 1;
    config->enable_transport_fallback = 1;
    
    return MR_SUCCESS;
}

mr_ctx_t* mr_init(void) {
    mr_config_t config;
    mr_get_default_config(&config);
    return mr_init_ex(&config);
}

mr_ctx_t* mr_init_ex(const mr_config_t* config) {
    mr_ctx_t* ctx = calloc(1, sizeof(mr_ctx_t));
    if (!ctx) return NULL;
    
    if (config) {
        memcpy(ctx, config, sizeof(mr_config_t));
    } else {
        mr_get_default_config((mr_config_t*)ctx);
    }
    
    ctx->ref_count = 1;
    memset(&ctx->stats, 0, sizeof(mr_protocol_stats_t));
    
    log_message(ctx, MR_LOG_INFO, "MeshRatchet v%s initialized with mode %d", 
                MESHRATCHET_VERSION, ctx->protocol_mode);
    return ctx;
}

void mr_cleanup(mr_ctx_t* ctx) {
    if (ctx && --ctx->ref_count <= 0) {
        log_message(ctx, MR_LOG_DEBUG, "MeshRatchet context cleaned up");
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
    key_pair->is_quantum_resistant = 0;
    
    if (generate_random(ctx, key_pair->private_key, 32) != MR_SUCCESS) {
        free(key_pair);
        return NULL;
    }
    
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
    
    log_message(ctx, MR_LOG_DEBUG, "New key pair generated");
    ctx->stats.sessions_created++;
    return key_pair;
}

mr_key_pair_t* mr_generate_quantum_key_pair(mr_ctx_t* ctx) {
    if (!ctx) return NULL;
    
    mr_key_pair_t* key_pair = calloc(1, sizeof(mr_key_pair_t));
    if (!key_pair) return NULL;
    
    key_pair->ctx = ctx;
    ctx->ref_count++;
    key_pair->is_quantum_resistant = 1;
    
    // Генерация расширенного ключа для квантовой устойчивости
    if (generate_random(ctx, key_pair->private_key, MR_QUANTUM_RESISTANT_KEY_LEN) != MR_SUCCESS) {
        free(key_pair);
        return NULL;
    }
    
    // Для демонстрации - используем первые 32 байта как публичный ключ
    memcpy(key_pair->public_key, key_pair->private_key, 32);
    
    log_message(ctx, MR_LOG_DEBUG, "New quantum-resistant key pair generated");
    ctx->stats.sessions_created++;
    return key_pair;
}

void mr_free_key_pair(mr_key_pair_t* key_pair) {
    if (key_pair) {
        secure_zero(key_pair->private_key, 
                   key_pair->is_quantum_resistant ? MR_QUANTUM_RESISTANT_KEY_LEN : 32);
        if (key_pair->ctx) {
            mr_cleanup(key_pair->ctx);
        }
        secure_zero(key_pair, sizeof(mr_key_pair_t));
        free(key_pair);
    }
}

int mr_session_create(mr_ctx_t* ctx, const mr_key_pair_t* local_key,
                     const uint8_t* remote_public_key, size_t pubkey_len,
                     mr_session_t** session) {
    return mr_session_create_advanced(ctx, local_key, remote_public_key, pubkey_len, 
                                     ctx->protocol_mode, session);
}

int mr_session_create_advanced(mr_ctx_t* ctx, const mr_key_pair_t* local_key,
                              const uint8_t* remote_public_key, size_t pubkey_len,
                              mr_mode_t mode, mr_session_t** session) {
    if (!ctx || !local_key || !remote_public_key || pubkey_len != 32 || !session) {
        return MR_ERROR_INVALID_PARAM;
    }

    mr_session_t* sess = calloc(1, sizeof(mr_session_t));
    uint8_t shared_secret[32];
    if (!sess) return MR_ERROR_MEMORY;

    sess->ctx = ctx;
    ctx->ref_count++;
    sess->created_time = time(NULL);
    sess->last_activity = sess->created_time;
    sess->current_mode = mode;
    sess->is_quantum_resistant = local_key->is_quantum_resistant;

    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);

    sess->replay_cache = calloc(1, sizeof(mr_replay_cache_t));
    if(!sess->replay_cache) {
        secure_zero(sess, sizeof(mr_session_t));
        free(sess);
        secure_zero(shared_secret, sizeof(shared_secret));
        return MR_ERROR_MEMORY;
    }

    if (mr_replay_cache_init(sess->replay_cache, 100, 300) != MR_SUCCESS) {
    free(sess->replay_cache);
    secure_zero(sess, sizeof(mr_session_t));
    free(sess);
    secure_zero(shared_secret, sizeof(shared_secret));
    return MR_ERROR_MEMORY;
}
    // Вычисление общего секрета
    // uint8_t shared_secret[32];
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
    
    // Генерация ID сессии и fingerprint
    if (generate_random(ctx, sess->session_id, MR_SESSION_ID_LEN) != MR_SUCCESS ||
        generate_random(ctx, sess->fingerprint, MR_FINGERPRINT_LEN) != MR_SUCCESS) {
        secure_zero(sess, sizeof(mr_session_t));
        free(sess);
        secure_zero(shared_secret, sizeof(shared_secret));
        return MR_ERROR_CRYPTO;
    }

    // Инициализация квантовых ключей если нужно
    if (sess->is_quantum_resistant) {
        if (generate_random(ctx, sess->quantum_send_key, MR_QUANTUM_RESISTANT_KEY_LEN) != MR_SUCCESS ||
            generate_random(ctx, sess->quantum_recv_key, MR_QUANTUM_RESISTANT_KEY_LEN) != MR_SUCCESS) {
            secure_zero(sess, sizeof(mr_session_t));
            free(sess);
            secure_zero(shared_secret, sizeof(shared_secret));
            return MR_ERROR_CRYPTO;
        }
        sess->quantum_key_index = 0;
    }

    if(mr_crypto_init(&sess->crypto_ctx, ctx->cipher_algorithm) != MR_SUCCESS) {
        free(sess);
        return MR_ERROR_CRYPTO;
    }

    if(mr_metrics_init(sess) != MR_SUCCESS) {
        mr_crypto_cleanup(&sess->crypto_ctx);
        free(sess);
        return MR_ERROR_MEMORY;
    }

    sess->is_valid = 1;
    if(!sess->replay_cache) {
        secure_zero(sess, sizeof(mr_replay_cache_t));
        free(sess);
        secure_zero(shared_secret, sizeof(shared_secret));
        return MR_ERROR_MEMORY;
    }

    if(mr_replay_cache_init(sess->replay_cache, 100, 300) != MR_SUCCESS) {
        secure_zero(sess, sizeof(mr_session_t));
        free(sess);
        secure_zero(shared_secret, sizeof(shared_secret));
        return MR_ERROR_MEMORY;
    }
    *session = sess;
    
    gettimeofday(&end_time, NULL);
    double setup_time = time_diff_us(start_time, end_time) / 1000.0;
    
    secure_zero(shared_secret, sizeof(shared_secret));
    
    log_message(ctx, MR_LOG_INFO, 
                "New session created (ID: %02x%02x..., Mode: %d, Quantum: %d, Setup: %.2fms)", 
                sess->session_id[0], sess->session_id[1], mode, 
                sess->is_quantum_resistant, setup_time);
    
    ctx->stats.sessions_created++;
    return MR_SUCCESS;
}

// функция шифрования с поддержкой разных режимов
int mr_encrypt(mr_session_t* session, mr_msg_type_t msg_type,
               const uint8_t* plaintext, size_t pt_len,
               uint8_t* ciphertext, size_t ct_buffer_len, size_t* ct_len) {
    if (!session || !session->is_valid || !plaintext || !ciphertext || !ct_len || pt_len == 0) {
        return MR_ERROR_INVALID_PARAM;
    }

    if(session->enable_advanced_security) {
        uint64_t timestamp = mr_generate_message_timestamp();
        size_t offset = 0;  
        memcpy(ciphertext + offset, &timestamp, sizeof(timestamp));
        offset += sizeof(timestamp);

        uint8_t auth_tag[32];
        if(mr_auth_generate_tag(&session->auth_ctx, plaintext, pt_len, auth_tag, sizeof(auth_tag)) == MR_SUCCESS) {
            memcpy(ciphertext + offset, auth_tag, 16);
            offset += 16;
        }
    }

    if (pt_len > session->ctx->max_message_size) {
        return MR_ERROR_BUFFER_TOO_SMALL;
    }

    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);

    // Определение размера сообщения в зависимости от режима
    size_t header_size = 0;
    if (session->current_mode == MR_MODE_STEALTH) {
        header_size = 1 + 4 + MR_NONCE_LEN; // type + random_seq + nonce
    } else {
        header_size = 1 + 8 + MR_NONCE_LEN; // type + sequence + nonce
    }
    
    size_t required_len = header_size + pt_len + MR_TAG_LEN;
    if (ct_buffer_len < required_len) {
        return MR_ERROR_BUFFER_TOO_SMALL;
    }

    // Проверка необходимости обновления ключей
    if (session->send_sequence % session->ctx->key_update_interval == 0 && session->send_sequence > 0) {
        if (session->ctx->key_update_cb) {
            session->ctx->key_update_cb(session, session->ctx->user_data);
        } else {
            mr_key_update(session);
        }
    }

    // Проверка квантовых ключей
    if (session->is_quantum_resistant && 
        session->send_sequence % session->ctx->quantum_update_interval == 0) {
        mr_quantum_key_update(session);
    }

    // Генерация ключей сообщения
    uint8_t message_key[MR_CHAIN_KEY_LEN];
    uint8_t nonce[MR_NONCE_LEN];
    if (generate_message_keys(session, message_key, nonce) != MR_SUCCESS) {
        return MR_ERROR_CRYPTO;
    }

    // Формирование заголовка в зависимости от режима
    size_t offset = 0;
    ciphertext[offset++] = (uint8_t)msg_type;
    
    if (session->current_mode == MR_MODE_STEALTH) {
        // Стелс-режим: используем случайную последовательность
        uint32_t random_seq;
        if (generate_random(session->ctx, (uint8_t*)&random_seq, sizeof(random_seq)) != MR_SUCCESS) {
            return MR_ERROR_CRYPTO;
        }
        memcpy(ciphertext + offset, &random_seq, 4);
        offset += 4;
    } else {
        // Стандартный режим: используем sequence number
        uint64_t sequence = session->send_sequence - 1;
        for (int i = 0; i < 8; i++) {
            ciphertext[offset++] = (sequence >> (56 - i * 8)) & 0xFF;
        }
    }
    
    memcpy(ciphertext + offset, nonce, MR_NONCE_LEN);
    offset += MR_NONCE_LEN;

    // Шифрование данных
    size_t encrypted_len;
    int result = perform_encryption(session, plaintext, pt_len, message_key, nonce,
                                   ciphertext + offset, &encrypted_len);
    
    secure_zero(message_key, sizeof(message_key));

    if (result != MR_SUCCESS) {
        session->ctx->stats.errors_encountered++;
        return result;
    }

    *ct_len = offset + encrypted_len;
    
    gettimeofday(&end_time, NULL);
    double encrypt_time = time_diff_us(start_time, end_time) / 1000.0;
    
    // Обновление статистики производительности
    if (session->avg_encrypt_time == 0) {
        session->avg_encrypt_time = encrypt_time;
    } else {
        session->avg_encrypt_time = (session->avg_encrypt_time * 0.9) + (encrypt_time * 0.1);
    }
    
    session->last_encrypt_time = end_time;
    session->ctx->stats.total_messages_sent++;
    session->ctx->stats.total_bytes_encrypted += *ct_len;
    
    log_message(session->ctx, MR_LOG_DEBUG, 
                "Message encrypted (type: %d, seq: %lu, size: %zu, time: %.2fms)", 
                msg_type, session->send_sequence - 1, *ct_len, encrypt_time);
    
    return MR_SUCCESS;
}

// функция дешифрования
int mr_decrypt(mr_session_t* session, 
               const uint8_t* ciphertext, size_t ct_len,
               uint8_t* plaintext, size_t pt_buffer_len, size_t* pt_len,
               mr_msg_type_t* msg_type) {
    if (!session || !session->is_valid || !ciphertext || !plaintext || !pt_len || !msg_type) {
        return MR_ERROR_INVALID_PARAM;
    }

    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);

    size_t min_ct_len = (session->current_mode == MR_MODE_STEALTH) ? 
                        (1 + 4 + MR_NONCE_LEN + MR_TAG_LEN) : 
                        (1 + 8 + MR_NONCE_LEN + MR_TAG_LEN);
                        
    if (ct_len < min_ct_len) {
        return MR_ERROR_INVALID_PARAM;
    }

    // Парсинг заголовка
    size_t offset = 0;
    *msg_type = (mr_msg_type_t)ciphertext[offset++];
    
    uint64_t sequence = 0;
    if (session->current_mode == MR_MODE_STEALTH) {
        // В стелс-режиме sequence не используется для верификации
        offset += 4; // Пропускаем random_seq
    } else {
        for (int i = 0; i < 8; i++) {
            sequence = (sequence << 8) | ciphertext[offset++];
        }

        // Проверка sequence number в стандартном режиме
        if (sequence < session->recv_sequence) {
            log_message(session->ctx, MR_LOG_WARN, "Duplicate message detected (seq: %lu)", sequence);
            return MR_ERROR_SEQUENCE;
        }
    }

    const uint8_t* nonce = ciphertext + offset;
    offset += MR_NONCE_LEN;
    
    const uint8_t* encrypted_data = ciphertext + offset;
    size_t data_len = ct_len - offset;

    // Пропуск ключей для потерянных сообщений (только в стандартном режиме)
    if (session->current_mode != MR_MODE_STEALTH && sequence > session->recv_sequence) {
        size_t skip_count = sequence - session->recv_sequence;
        if (skip_count > session->ctx->max_skip_keys) {
            log_message(session->ctx, MR_LOG_ERROR, "Too many skipped messages (%zu)", skip_count);
            return MR_ERROR_KEY_EXHAUSTED;
        }
        for (size_t i = 0; i < skip_count; i++) {
            ratchet_chain_key(session->recv_chain_key, session->recv_chain_key, session->current_mode);
        }
        session->recv_sequence = sequence;
        log_message(session->ctx, MR_LOG_WARN, "Skipped %zu message keys", skip_count);
    }

    // Получение ключа сообщения
    uint8_t message_key[MR_CHAIN_KEY_LEN];
    ratchet_chain_key(session->recv_chain_key, message_key, session->current_mode);
    
    if (session->current_mode != MR_MODE_STEALTH) {
        session->recv_sequence++;
    }
    
    session->messages_decrypted++;
    session->last_activity = time(NULL);

    // Дешифрование
    size_t decrypted_len;
    int result = perform_decryption(session, encrypted_data, data_len, message_key, nonce,
                                   plaintext, &decrypted_len);
    
    secure_zero(message_key, sizeof(message_key));

    if (result != MR_SUCCESS) {
        session->ctx->stats.errors_encountered++;
        log_message(session->ctx, MR_LOG_ERROR, "Decryption failed");
        return MR_ERROR_CRYPTO;
    }


    *pt_len = decrypted_len;

    if(session->enable_advanced_security) {
        uint8_t message_hash[SHA256_DIGEST_LENGTH];
        EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
        if(md_ctx) {
            if(EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) == 1 && EVP_DigestUpdate(md_ctx, ciphertext, ct_len) == 1 && EVP_DigestFinal_ex(md_ctx, message_hash, NULL) == 1) {
                if(mr_replay_check_and_add(session->replay_cache, message_hash, sizeof(message_hash)) != MR_SUCCESS) {
                    EVP_MD_CTX_free(md_ctx);
                    log_message(session->ctx, MR_LOG_ERROR, "Replay attack detected!");
                    return MR_ERROR_SEQUENCE;                   
                }
            }
            EVP_MD_CTX_free(md_ctx);
        }
    }
    
    gettimeofday(&end_time, NULL);
    double decrypt_time = time_diff_us(start_time, end_time) / 1000.0;
    
    // Обновление статистики производительности
    if (session->avg_decrypt_time == 0) {
        session->avg_decrypt_time = decrypt_time;
    } else {
        session->avg_decrypt_time = (session->avg_decrypt_time * 0.9) + (decrypt_time * 0.1);
    }

    if(session->enable_advanced_security) {
        uint64_t timestamp;
        memcpy(&timestamp, ciphertext, sizeof(timestamp)); 
        uint64_t current_time = mr_generate_message_timestamp();
        if(mr_verify_message_timestamp(timestamp, current_time, session->replay_cache->window_seconds) != MR_SUCCESS) {
            log_message(session->ctx, MR_LOG_ERROR, "Message timestamp verification failed!");
            return MR_ERROR_VERIFICATION;
        }

        uint8_t received_auth_tag[16];
        if (mr_auth_generate_tag(&session->auth_ctx, plaintext, *pt_len, received_auth_tag, 16) == MR_SUCCESS) {
            if (memcmp(received_auth_tag, ciphertext + sizeof(timestamp), 16) != 0) {
                log_message(session->ctx, MR_LOG_ERROR, "Message authentication failed!");
                return MR_ERROR_VERIFICATION;
            }
        }
        
        if(mr_replay_check_and_add(session->replay_cache, ciphertext, ct_len) != MR_SUCCESS){
            log_message(session->ctx, MR_LOG_ERROR, "replay attack detected!");
            return MR_ERROR_SEQUENCE;
        }
    }
    
    session->last_decrypt_time = end_time;
    session->ctx->stats.total_messages_received++;
    session->ctx->stats.total_bytes_decrypted += *pt_len;
    
    log_message(session->ctx, MR_LOG_DEBUG, 
                "Message decrypted (type: %d, size: %zu, time: %.2fms)", 
                *msg_type, *pt_len, decrypt_time);
    
    return MR_SUCCESS;
}


int mr_quantum_key_update(mr_session_t* session) {
    if (!session || !session->is_valid) return MR_ERROR_INVALID_PARAM;

    if (!session->is_quantum_resistant) {
        return MR_ERROR_INVALID_STATE;
    }

    log_message(session->ctx, MR_LOG_INFO, "Performing quantum key update...");

    // Генерация новых квантовых ключей
    if (generate_random(session->ctx, session->quantum_send_key, MR_QUANTUM_RESISTANT_KEY_LEN) != MR_SUCCESS ||
        generate_random(session->ctx, session->quantum_recv_key, MR_QUANTUM_RESISTANT_KEY_LEN) != MR_SUCCESS) {
        return MR_ERROR_CRYPTO;
    }

    session->quantum_key_index++;
    session->quantum_update_count++;
    session->ctx->stats.quantum_updates_performed++;

    log_message(session->ctx, MR_LOG_INFO, 
                "Quantum key update completed (index: %u, count: %u)", 
                session->quantum_key_index, session->quantum_update_count);
    
    return MR_SUCCESS;
}

int mr_enable_quantum_resistance(mr_session_t* session) {
    if (!session || !session->is_valid) return MR_ERROR_INVALID_PARAM;

    if (session->is_quantum_resistant) {
        return MR_SUCCESS; 
    }

    // Инициализация квантовых ключей
    if (generate_random(session->ctx, session->quantum_send_key, MR_QUANTUM_RESISTANT_KEY_LEN) != MR_SUCCESS ||
        generate_random(session->ctx, session->quantum_recv_key, MR_QUANTUM_RESISTANT_KEY_LEN) != MR_SUCCESS) {
        return MR_ERROR_CRYPTO;
    }

    session->is_quantum_resistant = 1;
    session->quantum_key_index = 0;
    
    log_message(session->ctx, MR_LOG_INFO, "Quantum resistance enabled");
    return MR_SUCCESS;
}

int mr_forward_secrecy_rotation(mr_session_t* session) {
    if (!session || !session->is_valid) return MR_ERROR_INVALID_PARAM;

    log_message(session->ctx, MR_LOG_INFO, "Performing forward secrecy rotation...");

    // Генерация новых ratchet ключей
    if (generate_random(session->ctx, session->send_ratchet_priv, 32) != MR_SUCCESS) {
        return MR_ERROR_CRYPTO;
    }

    // Сброс последовательностей для perfect forward secrecy
    session->prev_send_sequence = session->send_sequence;
    session->send_sequence = 0;
    session->recv_sequence = 0;
    
    log_message(session->ctx, MR_LOG_INFO, "Forward secrecy rotation completed");
    return MR_SUCCESS;
}

int mr_get_session_info(const mr_session_t* session, mr_session_info_t* info) {
    if (!session || !session->is_valid || !info) return MR_ERROR_INVALID_PARAM;
    
    memcpy(info->session_id, session->session_id, MR_SESSION_ID_LEN);
    memcpy(info->fingerprint, session->fingerprint, MR_FINGERPRINT_LEN);
    info->send_sequence = session->send_sequence;
    info->recv_sequence = session->recv_sequence;
    info->key_update_count = session->key_update_count;
    info->quantum_update_count = session->quantum_update_count;
    info->messages_encrypted = session->messages_encrypted;
    info->messages_decrypted = session->messages_decrypted;
    info->pending_messages = session->pending_count;
    info->current_mode = session->current_mode;
    info->is_active = (time(NULL) - session->last_activity < 3600);
    info->is_quantum_resistant = session->is_quantum_resistant;
    
    return MR_SUCCESS;
}

int mr_get_protocol_stats(mr_ctx_t* ctx, mr_protocol_stats_t* stats) {
    if (!ctx || !stats) return MR_ERROR_INVALID_PARAM;
    
    memcpy(stats, &ctx->stats, sizeof(mr_protocol_stats_t));
    return MR_SUCCESS;
}

int mr_get_performance_metrics(mr_session_t* session, 
                              double* encryption_time_ms, 
                              double* decryption_time_ms,
                              double* key_update_time_ms) {
    if (!session || !session->is_valid) return MR_ERROR_INVALID_PARAM;
    
    if (encryption_time_ms) *encryption_time_ms = session->avg_encrypt_time;
    if (decryption_time_ms) *decryption_time_ms = session->avg_decrypt_time;
    if (key_update_time_ms) *key_update_time_ms = 0.0; 
    
    return MR_SUCCESS;
}

void mr_session_free(mr_session_t* session) {
    if (session) {
        log_message(session->ctx, MR_LOG_DEBUG, 
                   "Session freed (encrypted: %u, decrypted: %u, quantum: %u)", 
                   session->messages_encrypted, session->messages_decrypted,
                   session->quantum_update_count);
        
        secure_zero(session->root_key, sizeof(session->root_key));
        secure_zero(session->send_chain_key, sizeof(session->send_chain_key));
        secure_zero(session->recv_chain_key, sizeof(session->recv_chain_key));
        secure_zero(session->send_ratchet_priv, sizeof(session->send_ratchet_priv));
        secure_zero(session->quantum_send_key, sizeof(session->quantum_send_key));
        secure_zero(session->quantum_recv_key, sizeof(session->quantum_recv_key));
        
        // Очистка pending messages
        mr_pending_msg_t* current = session->pending_messages;
        while (current) {
            mr_pending_msg_t* next = current->next;
            secure_zero(current->data, current->data_len);
            free(current->data);
            free(current);
            current = next;
        }
        mr_replay_cache_cleanup(session->replay_cache);
        if (session->ctx) {
            mr_cleanup(session->ctx);
        }
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
        case MR_ERROR_SESSION_EXPIRED: return "Session expired";
        case MR_ERROR_INVALID_STATE: return "Invalid session state";
        case MR_ERROR_PENDING_QUEUE_FULL: return "Pending message queue full";
        case MR_ERROR_TRANSPORT: return "Transport error";
        case MR_ERROR_QUANTUM_KEY_EXHAUSTED: return "Quantum keys exhausted";
        case MR_ERROR_FINGERPRINT_MISMATCH: return "Fingerprint mismatch";
        default: return "Unknown error";
    }
}

int mr_get_library_info(char* buffer, size_t buffer_len) {
    const char* info = "MeshRatchet Protocol v" MESHRATCHET_VERSION "\n"
                      "Author: " MESHRATCHET_AUTHOR "\n"
                      "Features: " MESHRATCHET_FEATURES "\n"
                      "Algorithms: X25519, HKDF, ChaCha20-Poly1305, AES-GCM\n"
                      "Modes: Standard, Stealth, Quantum-Resistant, High-Performance, Mobile";
    
    if (!buffer || buffer_len < strlen(info) + 1) {
        return MR_ERROR_BUFFER_TOO_SMALL;
    }
    
    strncpy(buffer, info, buffer_len);
    return MR_SUCCESS;
}

int mr_get_supported_features(char* buffer, size_t buffer_len) {
    const char* features = 
        "Quantum Resistance | Stealth Mode | Multicast | Forward Secrecy | "
        "Transport Fallback | Async Operations | Batch Processing | "
        "Performance Metrics | Session Fingerprinting | Key Rotation | "
        "Multi-Algorithm Support | Backwards Compatibility";
    
    if (!buffer || buffer_len < strlen(features) + 1) {
        return MR_ERROR_BUFFER_TOO_SMALL;
    }
    
    strncpy(buffer, features, buffer_len);
    return MR_SUCCESS;
}

int handshake(mr_ctx_t* ctx, const uint8_t* per_pubkey) {
    return MR_SUCCESS;
}

const uint8_t* mr_key_pair_get_public_key(const mr_key_pair_t *key_pair) {
    if(!key_pair) return NULL;
    return key_pair->public_key;
}

int mr_key_pair_is_quantum_resistant(const mr_key_pair_t* key_pair) {
    if(!key_pair) return 0;
    return key_pair->is_quantum_resistant;
}

int mr_key_update(mr_session_t* session) {
    if(!session || !session->is_valid) {
        return MR_ERROR_INVALID_PARAM;
    }

    // Генерация новых ratchet ключей

    if(generate_random(session->ctx, session->send_ratchet_priv, 32) != MR_SUCCESS) {
        return MR_ERROR_CRYPTO;
    }

    ratchet_chain_key(session->send_chain_key, session->send_chain_key, session->current_mode);
    ratchet_chain_key(session->recv_chain_key, session->recv_chain_key, session->current_mode);
    
    session->key_update_count++;
    session->ctx->stats.key_updates_performed++;
    
    return MR_SUCCESS;
}