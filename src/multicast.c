// src/multicast.c
#include "../include/meshratchet_internal.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t peer_id[16];
    mr_session_t* session;
} mr_multicast_peer_t;

struct mr_multicast_group {
    mr_ctx_t* ctx;
    mr_multicast_peer_t* peers;
    size_t peer_count;
    size_t peer_capacity;
};

mr_multicast_group_t* mr_multicast_group_create(mr_ctx_t* ctx) {
    mr_multicast_group_t* group = calloc(1, sizeof(mr_multicast_group_t));
    if (!group) return NULL;
    group->ctx = ctx;
    ctx->ref_count++;
    group->peer_capacity = 4;
    group->peers = calloc(group->peer_capacity, sizeof(mr_multicast_peer_t));
    if (!group->peers) {
        free(group);
        return NULL;
    }
    return group;
}

int mr_multicast_group_add_peer(mr_multicast_group_t* group, const uint8_t* peer_id, mr_session_t* session) {
    if (!group || !peer_id || !session) return MR_ERROR_INVALID_PARAM;
    
    if (group->peer_count >= group->peer_capacity) {
        size_t new_cap = group->peer_capacity * 2;
        mr_multicast_peer_t* new_peers = realloc(group->peers, new_cap * sizeof(mr_multicast_peer_t));
        if (!new_peers) return MR_ERROR_MEMORY;
        group->peers = new_peers;
        group->peer_capacity = new_cap;
    }
    
    memcpy(group->peers[group->peer_count].peer_id, peer_id, 16);
    group->peers[group->peer_count].session = session;
    group->peer_count++;
    return MR_SUCCESS;
}

int mr_multicast_encrypt(mr_multicast_group_t* group, mr_msg_type_t msg_type,
                        const uint8_t* plaintext, size_t pt_len,
                        uint8_t* ciphertext, size_t ct_buffer_len, size_t* ct_len) {
    if (!group || !plaintext || !ciphertext || !ct_len) return MR_ERROR_INVALID_PARAM;
    
    if (group->peer_count == 0) return MR_ERROR_INVALID_STATE;
    
    // Шифруем для первого пира 
    mr_session_t* first_session = group->peers[0].session;
    return mr_encrypt(first_session, msg_type, plaintext, pt_len, ciphertext, ct_buffer_len, ct_len);
}

void mr_multicast_group_free(mr_multicast_group_t* group) {
    if (group) {
        for (size_t i = 0; i < group->peer_count; i++) {
            // Не освобождаем session — это делает пользователь
        }
        free(group->peers);
        if (group->ctx) {
            mr_cleanup(group->ctx);
        }
        free(group);
    }
}