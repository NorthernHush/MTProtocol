#define MESHRATCHET_INTERNAL
#include "../include/meshratchet_internal.h"
#include "../utils/replay_protection.h"
#include "storage.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>  
#include <zlib.h>

size_t mr_storage_get_session_size(const mr_session_t* session) {
    if (!session) return 0;
    
    size_t size = sizeof(uint8_t) + 
                 MR_SESSION_ID_LEN +
                 MR_FINGERPRINT_LEN +
                 sizeof(uint64_t) * 3 + 
                 sizeof(uint32_t) * 4 + 
                 sizeof(time_t) * 2 +
                 MR_ROOT_KEY_LEN +
                 MR_CHAIN_KEY_LEN * 2 +
                 32 * 3; 
    
    if (session->is_quantum_resistant) {
        size += MR_QUANTUM_RESISTANT_KEY_LEN * 2 + sizeof(uint32_t);
    }
    
    return size + sizeof(uint32_t);
}

int mr_storage_serialize_session(const mr_session_t* session, uint8_t* buffer, size_t buffer_len) {
    if (!session || !session->is_valid || !buffer) {
        return MR_ERROR_INVALID_PARAM;
    }
    
    size_t required_size = mr_storage_get_session_size(session);
    if (buffer_len < required_size) {
        return MR_ERROR_BUFFER_TOO_SMALL;
    }
    
    size_t offset = 0;
    
    buffer[offset++] = 0x02; 
    
    memcpy(buffer + offset, session->session_id, MR_SESSION_ID_LEN);
    offset += MR_SESSION_ID_LEN;
    
    memcpy(buffer + offset, session->fingerprint, MR_FINGERPRINT_LEN);
    offset += MR_FINGERPRINT_LEN;
    
    memcpy(buffer + offset, &session->send_sequence, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    memcpy(buffer + offset, &session->recv_sequence, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    memcpy(buffer + offset, &session->prev_send_sequence, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    
    memcpy(buffer + offset, &session->key_update_count, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    memcpy(buffer + offset, &session->quantum_update_count, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    memcpy(buffer + offset, &session->messages_encrypted, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    memcpy(buffer + offset, &session->messages_decrypted, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    memcpy(buffer + offset, &session->created_time, sizeof(time_t));
    offset += sizeof(time_t);
    memcpy(buffer + offset, &session->last_activity, sizeof(time_t));
    offset += sizeof(time_t);
    
    memcpy(buffer + offset, session->root_key, MR_ROOT_KEY_LEN);
    offset += MR_ROOT_KEY_LEN;
    memcpy(buffer + offset, session->send_chain_key, MR_CHAIN_KEY_LEN);
    offset += MR_CHAIN_KEY_LEN;
    memcpy(buffer + offset, session->recv_chain_key, MR_CHAIN_KEY_LEN);
    offset += MR_CHAIN_KEY_LEN;
    memcpy(buffer + offset, session->send_ratchet_priv, 32);
    offset += 32;
    memcpy(buffer + offset, session->send_ratchet_pub, 32);
    offset += 32;
    memcpy(buffer + offset, session->recv_ratchet_pub, 32);
    offset += 32;
    
    if (session->is_quantum_resistant) {
        memcpy(buffer + offset, session->quantum_send_key, MR_QUANTUM_RESISTANT_KEY_LEN);
        offset += MR_QUANTUM_RESISTANT_KEY_LEN;
        memcpy(buffer + offset, session->quantum_recv_key, MR_QUANTUM_RESISTANT_KEY_LEN);
        offset += MR_QUANTUM_RESISTANT_KEY_LEN;
        memcpy(buffer + offset, &session->quantum_key_index, sizeof(uint32_t));
        offset += sizeof(uint32_t);
    }
    
    uint32_t crc = crc32(0, buffer, offset);
    memcpy(buffer + offset, &crc, sizeof(uint32_t));
    
    return MR_SUCCESS;
}

// добавлен возвратный тип и реализация
mr_session_t* mr_storage_deserialize_session(mr_ctx_t* ctx, const uint8_t* data, size_t data_len) {
    if (!ctx || !data || data_len < 100) {  // минимальный размер
        return NULL;
    }
    
    // Проверка версии
    if (data[0] != 0x02) {
        return NULL; // неподдерживаемая версия
    }
    
    size_t offset = 1;
    
    // Выделение памяти под сессию
    mr_session_t* session = calloc(1, sizeof(mr_session_t));
    if (!session) {
        return NULL;
    }
    
    // Копирование данных
    memcpy(session->session_id, data + offset, MR_SESSION_ID_LEN);
    offset += MR_SESSION_ID_LEN;
    
    memcpy(session->fingerprint, data + offset, MR_FINGERPRINT_LEN);
    offset += MR_FINGERPRINT_LEN;
    
    memcpy(&session->send_sequence, data + offset, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    memcpy(&session->recv_sequence, data + offset, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    memcpy(&session->prev_send_sequence, data + offset, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    
    memcpy(&session->key_update_count, data + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    memcpy(&session->quantum_update_count, data + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    memcpy(&session->messages_encrypted, data + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    memcpy(&session->messages_decrypted, data + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    memcpy(&session->created_time, data + offset, sizeof(time_t));
    offset += sizeof(time_t);
    memcpy(&session->last_activity, data + offset, sizeof(time_t));
    offset += sizeof(time_t);
    
    memcpy(session->root_key, data + offset, MR_ROOT_KEY_LEN);
    offset += MR_ROOT_KEY_LEN;
    memcpy(session->send_chain_key, data + offset, MR_CHAIN_KEY_LEN);
    offset += MR_CHAIN_KEY_LEN;
    memcpy(session->recv_chain_key, data + offset, MR_CHAIN_KEY_LEN);
    offset += MR_CHAIN_KEY_LEN;
    memcpy(session->send_ratchet_priv, data + offset, 32);
    offset += 32;
    memcpy(session->send_ratchet_pub, data + offset, 32);
    offset += 32;
    memcpy(session->recv_ratchet_pub, data + offset, 32);
    offset += 32;
    
    // Проверка CRC
    if (offset + sizeof(uint32_t) > data_len) {
        free(session);
        return NULL;
    }
    
    uint32_t stored_crc;
    memcpy(&stored_crc, data + offset, sizeof(uint32_t));
    uint32_t computed_crc = crc32(0, data, offset);
    
    if (stored_crc != computed_crc) {
        free(session);
        return NULL; // повреждённые данные
    }
    
    // Установка контекста
    session->ctx = ctx;
    session->is_valid = 1;
    
    // Определение квантовой устойчивости по размеру данных
    size_t expected_size_without_quantum = 1 + 
        MR_SESSION_ID_LEN + MR_FINGERPRINT_LEN +
        sizeof(uint64_t)*3 + sizeof(uint32_t)*4 +
        sizeof(time_t)*2 + MR_ROOT_KEY_LEN +
        MR_CHAIN_KEY_LEN*2 + 32*3 + sizeof(uint32_t);
    
    if (data_len > expected_size_without_quantum) {
        session->is_quantum_resistant = 1;
        memcpy(session->quantum_send_key, data + offset, MR_QUANTUM_RESISTANT_KEY_LEN);
        offset += MR_QUANTUM_RESISTANT_KEY_LEN;
        memcpy(session->quantum_recv_key, data + offset, MR_QUANTUM_RESISTANT_KEY_LEN);
        offset += MR_QUANTUM_RESISTANT_KEY_LEN;
        memcpy(&session->quantum_key_index, data + offset, sizeof(uint32_t));
    }
    
    // Инициализация replay cache 
    session->replay_cache = calloc(1, sizeof(mr_replay_cache_t));
    if (session->replay_cache) {
        if (mr_replay_cache_init(session->replay_cache, 100, 300) != MR_SUCCESS) {
            free(session->replay_cache);
            session->replay_cache = NULL;
        }
    }
    
    return session;
}