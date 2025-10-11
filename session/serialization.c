// session/serialization.c
#include "../session/storage.h"
#include <string.h>

int mr_session_serialize(mr_session_t* session, uint8_t* out, size_t* len) {
    if (!session || !out || !len) return MR_ERROR_INVALID_PARAM;
    
    if (*len < 512) return MR_ERROR_BUFFER_TOO_SMALL;
    
    // Простой бинарный формат: [version][session_id][keys...]
    size_t offset = 0;
    out[offset++] = 1; // версия
    
    memcpy(out + offset, session->session_id, MR_SESSION_ID_LEN);
    offset += MR_SESSION_ID_LEN;
    
    memcpy(out + offset, session->root_key, MR_ROOT_KEY_LEN);
    offset += MR_ROOT_KEY_LEN;
    
    memcpy(out + offset, session->send_chain_key, MR_CHAIN_KEY_LEN);
    offset += MR_CHAIN_KEY_LEN;
    
    memcpy(out + offset, session->recv_chain_key, MR_CHAIN_KEY_LEN);
    offset += MR_CHAIN_KEY_LEN;
    
    memcpy(out + offset, session->send_ratchet_priv, 32);
    offset += 32;
    
    memcpy(out + offset, session->send_ratchet_pub, 32);
    offset += 32;
    
    memcpy(out + offset, session->recv_ratchet_pub, 32);
    offset += 32;
    
    if (session->is_quantum_resistant) {
        memcpy(out + offset, session->quantum_send_key, MR_QUANTUM_RESISTANT_KEY_LEN);
        offset += MR_QUANTUM_RESISTANT_KEY_LEN;
        memcpy(out + offset, session->quantum_recv_key, MR_QUANTUM_RESISTANT_KEY_LEN);
        offset += MR_QUANTUM_RESISTANT_KEY_LEN;
    }
    
    memcpy(out + offset, &session->send_sequence, sizeof(session->send_sequence));
    offset += sizeof(session->send_sequence);
    
    memcpy(out + offset, &session->recv_sequence, sizeof(session->recv_sequence));
    offset += sizeof(session->recv_sequence);
    
    *len = offset;
    return MR_SUCCESS;
}

mr_session_t* mr_session_deserialize(mr_ctx_t* ctx, const uint8_t* data, size_t len) {
    if (!ctx || !data || len < 512) return NULL;
    
    mr_session_t* sess = calloc(1, sizeof(mr_session_t));
    if (!sess) return NULL;
    
    sess->ctx = ctx;
    ctx->ref_count++;
    sess->created_time = time(NULL);
    sess->last_activity = sess->created_time;
    sess->is_valid = 1;
    
    size_t offset = 1; // пропускаем версию
    
    memcpy(sess->session_id, data + offset, MR_SESSION_ID_LEN);
    offset += MR_SESSION_ID_LEN;
    
    memcpy(sess->root_key, data + offset, MR_ROOT_KEY_LEN);
    offset += MR_ROOT_KEY_LEN;
    
    memcpy(sess->send_chain_key, data + offset, MR_CHAIN_KEY_LEN);
    offset += MR_CHAIN_KEY_LEN;
    
    memcpy(sess->recv_chain_key, data + offset, MR_CHAIN_KEY_LEN);
    offset += MR_CHAIN_KEY_LEN;
    
    memcpy(sess->send_ratchet_priv, data + offset, 32);
    offset += 32;
    
    memcpy(sess->send_ratchet_pub, data + offset, 32);
    offset += 32;
    
    memcpy(sess->recv_ratchet_pub, data + offset, 32);
    offset += 32;
    
    // Пока не проверяем квантовую устойчивость — можно добавить флаг
    if (len > offset + MR_QUANTUM_RESISTANT_KEY_LEN * 2) {
        memcpy(sess->quantum_send_key, data + offset, MR_QUANTUM_RESISTANT_KEY_LEN);
        offset += MR_QUANTUM_RESISTANT_KEY_LEN;
        memcpy(sess->quantum_recv_key, data + offset, MR_QUANTUM_RESISTANT_KEY_LEN);
        offset += MR_QUANTUM_RESISTANT_KEY_LEN;
        sess->is_quantum_resistant = 1;
    }
    
    memcpy(&sess->send_sequence, data + offset, sizeof(sess->send_sequence));
    offset += sizeof(sess->send_sequence);
    
    memcpy(&sess->recv_sequence, data + offset, sizeof(sess->recv_sequence));
    offset += sizeof(sess->recv_sequence);
    
    return sess;
}