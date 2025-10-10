#ifndef MESHRATCHET_H
#define MESHRATCHET_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Версия протокола
#define MESHRATCHET_VERSION "2.0.0"
#define MESHRATCHET_AUTHOR "Mesh Security Team"

// Константы
#define MR_CHAIN_KEY_LEN      32
#define MR_ROOT_KEY_LEN       32
#define MR_NONCE_LEN          12
#define MR_TAG_LEN            16
#define MR_MAX_MSG_SIZE       65536
#define MR_MAX_SKIP_KEYS      1000
#define MR_KEY_UPDATE_INTERVAL 1000
#define MR_SESSION_ID_LEN     32

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
    MR_ERROR_INVALID_STATE = -10
} mr_result_t;

// Типы сообщений
typedef enum {
    MR_MSG_TYPE_APPLICATION = 0,
    MR_MSG_TYPE_KEY_EXCHANGE = 1,
    MR_MSG_TYPE_KEY_UPDATE = 2,
    MR_MSG_TYPE_HEARTBEAT = 3,
    MR_MSG_TYPE_CONTROL = 4,
    MR_MSG_TYPE_EMERGENCY = 5
} mr_msg_type_t;

// Уровни логирования
typedef enum {
    MR_LOG_ERROR = 0,
    MR_LOG_WARN = 1,
    MR_LOG_INFO = 2,
    MR_LOG_DEBUG = 3
} mr_log_level_t;

// Структуры (непрозрачные)
typedef struct mr_ctx mr_ctx_t;
typedef struct mr_session mr_session_t;
typedef struct mr_key_pair mr_key_pair_t;

// Callback-функции
typedef void (*mr_log_cb_t)(mr_log_level_t level, const char* message, void* user_data);
typedef int (*mr_random_cb_t)(uint8_t* buffer, size_t len, void* user_data);
typedef int (*mr_key_update_cb_t)(mr_session_t* session, void* user_data);

// Конфигурация
typedef struct {
    mr_log_cb_t log_callback;
    mr_random_cb_t random_callback;
    mr_key_update_cb_t key_update_callback;
    void* user_data;
    uint32_t max_message_size;
    uint32_t key_update_interval;
    uint32_t max_skip_keys;
    int enable_serialization;
    int enable_batch_operations;
} mr_config_t;

// Информация о сессии
typedef struct {
    uint8_t session_id[MR_SESSION_ID_LEN];
    uint64_t send_sequence;
    uint64_t recv_sequence;
    uint32_t key_update_count;
    uint32_t messages_encrypted;
    uint32_t messages_decrypted;
    uint8_t is_active;
} mr_session_info_t;

// ===== ОСНОВНЫЕ ФУНКЦИИ =====

// Инициализация/деинициализация
mr_ctx_t* mr_init(void);
mr_ctx_t* mr_init_ex(const mr_config_t* config);
void mr_cleanup(mr_ctx_t* ctx);

// Конфигурация
int mr_set_config(mr_ctx_t* ctx, const mr_config_t* config);
int mr_get_default_config(mr_config_t* config);

// Генерация ключевой пары
mr_key_pair_t* mr_generate_key_pair(mr_ctx_t* ctx);
void mr_free_key_pair(mr_key_pair_t* key_pair);
int mr_export_public_key(const mr_key_pair_t* key_pair, uint8_t* buffer, size_t buffer_len);
int mr_export_private_key(const mr_key_pair_t* key_pair, uint8_t* buffer, size_t buffer_len);
mr_key_pair_t* mr_import_key_pair(mr_ctx_t* ctx, const uint8_t* private_key, size_t key_len);

// Управление сессиями
int mr_session_create(mr_ctx_t* ctx, const mr_key_pair_t* local_key,
                     const uint8_t* remote_public_key, size_t pubkey_len,
                     mr_session_t** session);
int mr_session_create_mutual(mr_ctx_t* ctx, const mr_key_pair_t* local_key,
                            const mr_key_pair_t* remote_key, mr_session_t** session);
void mr_session_free(mr_session_t* session);

// Сериализация сессии
size_t mr_session_get_size(const mr_session_t* session);
int mr_session_export(const mr_session_t* session, uint8_t* buffer, size_t buffer_len);
mr_session_t* mr_session_import(mr_ctx_t* ctx, const uint8_t* data, size_t data_len);

// ===== ОПЕРАЦИИ С СООБЩЕНИЯМИ =====

// Шифрование
int mr_encrypt(mr_session_t* session, mr_msg_type_t msg_type,
               const uint8_t* plaintext, size_t pt_len,
               uint8_t* ciphertext, size_t ct_buffer_len, size_t* ct_len);

// Дешифрование
int mr_decrypt(mr_session_t* session, 
               const uint8_t* ciphertext, size_t ct_len,
               uint8_t* plaintext, size_t pt_buffer_len, size_t* pt_len,
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

// ===== ДОПОЛНИТЕЛЬНЫЕ ФУНКЦИИ =====

// Управление ключами
int mr_key_update(mr_session_t* session);
int mr_emergency_key_update(mr_session_t* session);
int mr_get_message_keys_remaining(const mr_session_t* session, size_t* send_keys, size_t* recv_keys);
int mr_skip_message_keys(mr_session_t* session, size_t count);

// Информация о сессии
int mr_get_session_info(const mr_session_t* session, mr_session_info_t* info);
int mr_get_sequence_numbers(const mr_session_t* session, uint64_t* send_seq, uint64_t* recv_seq);
int mr_session_is_valid(const mr_session_t* session);
int mr_session_is_active(const mr_session_t* session);

// Утилиты
const char* mr_error_string(mr_result_t error);
int mr_get_version(char* buffer, size_t buffer_len);
int mr_get_library_info(char* buffer, size_t buffer_len);

// Отладочные функции
int mr_dump_session_state(const mr_session_t* session, char* buffer, size_t buffer_len);

#ifdef __cplusplus
}
#endif

#endif // MESHRATCHET_H