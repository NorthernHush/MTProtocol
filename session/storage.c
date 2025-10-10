#include "storage.h"
#include <stdio.h>
#include <string.h>
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

mr_storage_deserialize_session(mr_ctx_t* ctx, const uint8_t* data, size_t data_len)