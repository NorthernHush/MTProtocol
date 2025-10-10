#ifndef MESHRATCHET_H
#define MESHRATCHET_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Версия протокола
#define MESHRATCHET_VERSION "3.0.0"
#define MESHRATCHET_AUTHOR "Mesh Security Team"
#define MESHRATCHET_FEATURES "Quantum-Resistant, Multi-Transport, Stealth Mode"

// Константы
#define MR_CHAIN_KEY_LEN      32
#define MR_ROOT_KEY_LEN       32
#define MR_NONCE_LEN          12
#define MR_TAG_LEN            16
#define MR_MAX_MSG_SIZE       65536
#define MR_MAX_SKIP_KEYS      1000
#define MR_KEY_UPDATE_INTERVAL 1000
#define MR_SESSION_ID_LEN     32
#define MR_FINGERPRINT_LEN    16
#define MR_MAX_PENDING_MSGS   100
#define MR_QUANTUM_RESISTANT_KEY_LEN 64

// Режимы работы протокола
typedef enum {
    MR_MODE_STANDARD = 0,      // Стандартный режим
    MR_MODE_STEALTH = 1,       // Стелс-режим (минимальная метаданная)
    MR_MODE_QUANTUM = 2,       // Квантово-устойчивый режим
    MR_MODE_HIGH_PERF = 3,     // Высокопроизводительный режим
    MR_MODE_MOBILE = 4         // Оптимизирован для мобильных устройств
} mr_mode_t;

// Алгоритмы шифрования
typedef enum {
    MR_CIPHER_CHACHA20 = 0,
    MR_CIPHER_AES256_GCM = 1,
    MR_CIPHER_AES128_GCM = 2
} mr_cipher_t;

// Коды ошибок
typedef enum {
    MR_SUCCESS = 0,
    MR_ERROR_INVALID_PARAM = -1,
    MR_ERROR_MEMORY = -2,
    MR_ERROR_CRYPTO = -3,
    MR_ERROR_SESSION = -4,
    MR_ERROR_SEQUENCE = -5,
    MR_ERROR_VERIFICATION = -6,
    MR_ERROR_BUFFER_TOO_SMALL = -7,
    MR_ERROR_KEY_EXHAUSTED = -8,
    MR_ERROR_SESSION_EXPIRED = -9,
    MR_ERROR_INVALID_STATE = -10,
    MR_ERROR_PENDING_QUEUE_FULL = -11,
    MR_ERROR_TRANSPORT = -12,
    MR_ERROR_QUANTUM_KEY_EXHAUSTED = -13,
    MR_ERROR_FINGERPRINT_MISMATCH = -14
} mr_result_t;

// Типы сообщений
typedef enum {
    MR_MSG_TYPE_APPLICATION = 0,
    MR_MSG_TYPE_KEY_EXCHANGE = 1,
    MR_MSG_TYPE_KEY_UPDATE = 2,
    MR_MSG_TYPE_HEARTBEAT = 3,
    MR_MSG_TYPE_CONTROL = 4,
    MR_MSG_TYPE_EMERGENCY = 5,
    MR_MSG_TYPE_MULTICAST = 6,
    MR_MSG_TYPE_FORWARD_SECRECY_ROTATION = 7,
    MR_MSG_TYPE_QUANTUM_UPDATE = 8
} mr_msg_type_t;

// Уровни логирования
typedef enum {
    MR_LOG_ERROR = 0,
    MR_LOG_WARN = 1,
    MR_LOG_INFO = 2,
    MR_LOG_DEBUG = 3,
    MR_LOG_TRACE = 4
} mr_log_level_t;

// Транспортные протоколы
typedef enum {
    MR_TRANSPORT_TCP = 0,
    MR_TRANSPORT_UDP = 1,
    MR_TRANSPORT_BLE = 2,
    MR_TRANSPORT_LORA = 3,
    MR_TRANSPORT_QUIC = 4
} mr_transport_t;

// Структуры (непрозрачные)
typedef struct mr_ctx mr_ctx_t;
typedef struct mr_session mr_session_t;
typedef struct mr_key_pair mr_key_pair_t;
typedef struct mr_pending_msg mr_pending_msg_t;
typedef struct mr_quantum_ctx mr_quantum_ctx_t;

// Callback-функции
typedef void (*mr_log_cb_t)(mr_log_level_t level, const char* message, void* user_data);
typedef int (*mr_random_cb_t)(uint8_t* buffer, size_t len, void* user_data);
typedef int (*mr_key_update_cb_t)(mr_session_t* session, void* user_data);
typedef int (*mr_transport_send_cb_t)(const uint8_t* data, size_t len, void* user_data);
typedef int (*mr_transport_recv_cb_t)(uint8_t* buffer, size_t buffer_len, size_t* received, void* user_data);
typedef int (*mr_quantum_update_cb_t)(mr_session_t* session, void* user_data);

// Конфигурация
typedef struct {
    mr_log_cb_t log_callback;
    mr_random_cb_t random_callback;
    mr_key_update_cb_t key_update_callback;
    mr_quantum_update_cb_t quantum_update_callback;
    mr_transport_send_cb_t transport_send_callback;
    mr_transport_recv_cb_t transport_recv_callback;
    void* user_data;
    
    // Настройки протокола
    uint32_t max_message_size;
    uint32_t key_update_interval;
    uint32_t max_skip_keys;
    uint32_t quantum_update_interval;
    mr_mode_t protocol_mode;
    mr_cipher_t cipher_algorithm;
    mr_transport_t transport;
    
    // Флаги функций
    int enable_serialization;
    int enable_batch_operations;
    int enable_quantum_resistance;
    int enable_stealth_mode;
    int enable_multicast;
    int enable_forward_secrecy;
    int enable_transport_fallback;
} mr_config_t;

// Информация о сессии
typedef struct {
    uint8_t session_id[MR_SESSION_ID_LEN];
    uint8_t fingerprint[MR_FINGERPRINT_LEN];
    uint64_t send_sequence;
    uint64_t recv_sequence;
    uint32_t key_update_count;
    uint32_t quantum_update_count;
    uint32_t messages_encrypted;
    uint32_t messages_decrypted;
    uint32_t pending_messages;
    mr_mode_t current_mode;
    uint8_t is_active;
    uint8_t is_quantum_resistant;
} mr_session_info_t;

// Статистика протокола
typedef struct {
    uint64_t total_messages_sent;
    uint64_t total_messages_received;
    uint64_t total_bytes_encrypted;
    uint64_t total_bytes_decrypted;
    uint32_t key_updates_performed;
    uint32_t quantum_updates_performed;
    uint32_t sessions_created;
    uint32_t errors_encountered;
    double average_encryption_time_ms;
    double average_decryption_time_ms;
} mr_protocol_stats_t;

// ===== ОСНОВНЫЕ ФУНКЦИИ =====

// Инициализация/деинициализация
mr_ctx_t* mr_init(void);
mr_ctx_t* mr_init_ex(const mr_config_t* config);
void mr_cleanup(mr_ctx_t* ctx);

// Конфигурация
int mr_set_config(mr_ctx_t* ctx, const mr_config_t* config);
int mr_get_default_config(mr_config_t* config);
int mr_set_protocol_mode(mr_ctx_t* ctx, mr_mode_t mode);
int mr_set_cipher_algorithm(mr_ctx_t* ctx, mr_cipher_t cipher);

// Генерация ключевой пары
mr_key_pair_t* mr_generate_key_pair(mr_ctx_t* ctx);
mr_key_pair_t* mr_generate_quantum_key_pair(mr_ctx_t* ctx);
void mr_free_key_pair(mr_key_pair_t* key_pair);
int mr_export_public_key(const mr_key_pair_t* key_pair, uint8_t* buffer, size_t buffer_len);
int mr_export_private_key(const mr_key_pair_t* key_pair, uint8_t* buffer, size_t buffer_len);
mr_key_pair_t* mr_import_key_pair(mr_ctx_t* ctx, const uint8_t* private_key, size_t key_len);

// Управление сессиями
int mr_session_create(mr_ctx_t* ctx, const mr_key_pair_t* local_key,
                     const uint8_t* remote_public_key, size_t pubkey_len,
                     mr_session_t** session);
int mr_session_create_advanced(mr_ctx_t* ctx, const mr_key_pair_t* local_key,
                              const uint8_t* remote_public_key, size_t pubkey_len,
                              mr_mode_t mode, mr_session_t** session);
int mr_session_create_multicast(mr_ctx_t* ctx, const mr_key_pair_t* local_key,
                               const uint8_t** remote_public_keys, const size_t* pubkey_lens,
                               size_t num_peers, mr_session_t** session);
void mr_session_free(mr_session_t* session);

// Сериализация сессии
size_t mr_session_get_size(const mr_session_t* session);
int mr_session_export(const mr_session_t* session, uint8_t* buffer, size_t buffer_len);
mr_session_t* mr_session_import(mr_ctx_t* ctx, const uint8_t* data, size_t data_len);

// ===== РАСШИРЕННЫЕ ОПЕРАЦИИ С СООБЩЕНИЯМИ =====

// Шифрование
int mr_encrypt(mr_session_t* session, mr_msg_type_t msg_type,
               const uint8_t* plaintext, size_t pt_len,
               uint8_t* ciphertext, size_t ct_buffer_len, size_t* ct_len);

// Дешифрование
int mr_decrypt(mr_session_t* session, 
               const uint8_t* ciphertext, size_t ct_len,
               uint8_t* plaintext, size_t pt_buffer_len, size_t* pt_len,
               mr_msg_type_t* msg_type);

// Асинхронное шифрование/дешифрование
int mr_encrypt_async(mr_session_t* session, mr_msg_type_t msg_type,
                    const uint8_t* plaintext, size_t pt_len,
                    uint64_t* message_id);
int mr_decrypt_async(mr_session_t* session,
                    const uint8_t* ciphertext, size_t ct_len,
                    uint64_t* message_id);
int mr_get_async_result(mr_session_t* session, uint64_t message_id,
                       uint8_t* buffer, size_t buffer_len, size_t* data_len,
                       mr_msg_type_t* msg_type);

// Пакетное шифрование/дешифрование
int mr_encrypt_batch(mr_session_t* session, mr_msg_type_t msg_type,
                    const uint8_t** plaintexts, const size_t* pt_lens,
                    uint8_t** ciphertexts, size_t* ct_lens,
                    size_t count);

int mr_decrypt_batch(mr_session_t* session,
                    const uint8_t** ciphertexts, const size_t* ct_lens,
                    uint8_t** plaintexts, size_t* pt_lens,
                    mr_msg_type_t* msg_types, size_t count);

// Мультикаст операции
int mr_encrypt_multicast(mr_session_t* session, mr_msg_type_t msg_type,
                        const uint8_t* plaintext, size_t pt_len,
                        uint8_t* ciphertext, size_t ct_buffer_len, size_t* ct_len);
int mr_decrypt_multicast(mr_session_t* session,
                        const uint8_t* ciphertext, size_t ct_len,
                        uint8_t* plaintext, size_t pt_buffer_len, size_t* pt_len,
                        mr_msg_type_t* msg_type, uint8_t* sender_fingerprint);

// ===== КВАНТОВО-УСТОЙЧИВЫЕ ФУНКЦИИ =====

// Квантово-устойчивые операции
int mr_quantum_key_update(mr_session_t* session);
int mr_enable_quantum_resistance(mr_session_t* session);
int mr_disable_quantum_resistance(mr_session_t* session);
int mr_get_quantum_keys_remaining(const mr_session_t* session, size_t* remaining);

// ===== УПРАВЛЕНИЕ КЛЮЧАМИ И БЕЗОПАСНОСТЬ =====

// Управление ключами
int mr_key_update(mr_session_t* session);
int mr_emergency_key_update(mr_session_t* session);
int mr_forward_secrecy_rotation(mr_session_t* session);
int mr_get_message_keys_remaining(const mr_session_t* session, size_t* send_keys, size_t* recv_keys);
int mr_skip_message_keys(mr_session_t* session, size_t count);

// Верификация и аутентификация
int mr_verify_session_fingerprint(const mr_session_t* session, const uint8_t* expected_fingerprint);
int mr_generate_session_fingerprint(const mr_session_t* session, uint8_t* fingerprint, size_t fingerprint_len);
int mr_authenticate_message(mr_session_t* session, const uint8_t* message, size_t message_len,
                           uint8_t* auth_tag, size_t auth_tag_len);

// ===== ИНФОРМАЦИЯ И МОНИТОРИНГ =====

// Информация о сессии
int mr_get_session_info(const mr_session_t* session, mr_session_info_t* info);
int mr_get_sequence_numbers(const mr_session_t* session, uint64_t* send_seq, uint64_t* recv_seq);
int mr_session_is_valid(const mr_session_t* session);
int mr_session_is_active(const mr_session_t* session);
int mr_get_session_health(const mr_session_t* session);

// Статистика и мониторинг
int mr_get_protocol_stats(mr_ctx_t* ctx, mr_protocol_stats_t* stats);
int mr_reset_protocol_stats(mr_ctx_t* ctx);
int mr_get_performance_metrics(mr_session_t* session, 
                              double* encryption_time_ms, 
                              double* decryption_time_ms,
                              double* key_update_time_ms);

// ===== ТРАНСПОРТ И СЕТЕВЫЕ ФУНКЦИИ =====

// Транспортные функции
int mr_send_message(mr_session_t* session, const uint8_t* data, size_t data_len);
int mr_receive_message(mr_session_t* session, uint8_t* buffer, size_t buffer_len, size_t* received);
int mr_set_transport(mr_session_t* session, mr_transport_t transport);
int mr_transport_fallback(mr_session_t* session, mr_transport_t primary, mr_transport_t fallback);

// ===== УТИЛИТЫ И ДОПОЛНИТЕЛЬНЫЕ ФУНКЦИИ =====

// Утилиты
const char* mr_error_string(mr_result_t error);
int mr_get_version(char* buffer, size_t buffer_len);
int mr_get_library_info(char* buffer, size_t buffer_len);
int mr_get_supported_features(char* buffer, size_t buffer_len);

// Отладочные функции
int mr_dump_session_state(const mr_session_t* session, char* buffer, size_t buffer_len);
int mr_validate_cryptographic_primitives(void);
int mr_self_test(mr_ctx_t* ctx);

// Функции совместимости
int mr_enable_backwards_compatibility(mr_session_t* session, uint32_t version);
int mr_disable_backwards_compatibility(mr_session_t* session);

#ifdef __cplusplus
}
#endif

#endif // MESHRATCHET_H