// include/meshratchet_internal.h
#ifndef MESHRATCHET_INTERNAL_H
#define MESHRATCHET_INTERNAL_H

#include "meshratchet.h"
#include <time.h>
#include <sys/time.h>
#include "../crypto/crypto.h"
#include "../crypto/auth.h"
#include "../utils/metrics.h"
#include "../utils/replay_protection.h"

// Полное определение структур (только для внутреннего использования)
struct mr_session {
    uint8_t root_key[MR_ROOT_KEY_LEN];
    uint8_t send_chain_key[MR_CHAIN_KEY_LEN];
    uint8_t recv_chain_key[MR_CHAIN_KEY_LEN];
    uint8_t send_ratchet_priv[32];
    uint8_t send_ratchet_pub[32];
    uint8_t recv_ratchet_pub[32];
    
    uint8_t quantum_send_key[MR_QUANTUM_RESISTANT_KEY_LEN];
    uint8_t quantum_recv_key[MR_QUANTUM_RESISTANT_KEY_LEN];
    uint32_t quantum_key_index;
    
    uint64_t send_sequence;
    uint64_t recv_sequence;
    uint64_t prev_send_sequence;
    uint32_t key_update_count;
    uint32_t quantum_update_count;
    uint32_t messages_encrypted;
    uint32_t messages_decrypted;
    uint8_t session_id[MR_SESSION_ID_LEN];
    uint8_t fingerprint[MR_FINGERPRINT_LEN];
    
    mr_ctx_t* ctx;
    int is_valid;
    int is_quantum_resistant;
    time_t created_time;
    time_t last_activity;
    mr_mode_t current_mode;
    
    mr_pending_msg_t* pending_messages;
    uint32_t pending_count;
    
    struct timeval last_encrypt_time;
    struct timeval last_decrypt_time;
    double avg_encrypt_time;
    double avg_decrypt_time;

    mr_session_metrics_t metrics;
    mr_crypto_ctx_t crypto_ctx;
    uint8_t serialized_data[512];
    mr_health_status_t health_status;

    mr_replay_cache_t* replay_cache;
    mr_auth_ctx_t auth_ctx;
    uint8_t enable_advanced_security;
    uint32_t security_level;
};

struct mr_ctx {
    mr_log_cb_t log_cb;
    mr_random_cb_t random_cb;
    mr_key_update_cb_t key_update_cb;
    mr_quantum_update_cb_t quantum_update_cb;
    mr_transport_send_cb_t transport_send_cb;
    mr_transport_recv_cb_t transport_recv_cb;
    void* user_data;
    
    uint32_t max_message_size;
    uint32_t key_update_interval;
    uint32_t max_skip_keys;
    uint32_t quantum_update_interval;
    mr_mode_t protocol_mode;
    mr_cipher_t cipher_algorithm;
    mr_transport_t transport;
    
    int enable_serialization;
    int enable_batch_operations;
    int enable_quantum_resistance;
    int enable_stealth_mode;
    int enable_multicast;
    int enable_forward_secrecy;
    int enable_transport_fallback;
    
    int ref_count;
    mr_protocol_stats_t stats;
};

struct mr_key_pair {
    uint8_t public_key[32];
    uint8_t private_key[32];
    int is_quantum_resistant;
    mr_ctx_t* ctx;
};

struct mr_pending_msg {
    uint64_t message_id;
    uint8_t* data;
    size_t data_len;
    mr_msg_type_t msg_type;
    int is_encrypted;
    struct mr_pending_msg* next;
};

#endif // MESHRATCHET_INTERNAL_H