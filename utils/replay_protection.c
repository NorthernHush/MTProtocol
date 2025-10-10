#include "replay_protection.h"
#include <openssl/sha.h>
#include <stdint.h>
#include <time.h>

int mr_replay_protection_init(mr_session_t *session, size_t cache_size, uint32_t time_window_seconds) {
    if(!session || cache_size == 0) return MR_ERROR_INVALID_PARAM;

    session->replay_cache = calloc(1, sizeof(mr_replay_cache_t));
    if(!session->replay_cache) return MR_ERROR_MEMORY;

    session->replay_cache->entries = calloc(cache_size, sizeof(mr_replay_entry_t));
    if(!session->replay_cache->entries) {
        free(session->replay_cache);
        return MR_ERROR_MEMORY;
    }

    session->replay_cache->capacity = cache_size; 
    session->replay_cache->count = 0;
    session->replay_cache->window_seconds = time_window_seconds;

    return MR_SUCCES;
}

int mr_replay_check_and_add(mr_session_t* session, const uint8_t* message, size_t message_len, uint64_t message_id) {
    if(!session || !session->replay_cache || !message) {
        return MR_ERROR_INVALID_PARAM;
    }
    
    uint8_t message_hash[SHA256_DIGEST_LENGTH];
    SHA256(message, message_len, message_hash);

    for(size_t i = 0; i < session->replay_cache->count; i++) {
        if(memcpy(session->replay_cache->entries[i].message_hash, message_hash, SHA256, SHA256_DIGEST_LENGTH) == 0) {
            log_message(session->ctx, MR_LOG_WARN, "Replay attack detected! Duplicate message found");
            return MR_ERROR_SEQUENCE;    
        }
    }

    size_t index = session->replay_cache->count;
    if(index => session->replay_cache->capacity) {
        memmove(session->replay_cache->entries, session->replay_cache->entries + 1, (session->replay_cache->capacity - 1) * sizeof(mr_replay_entry_t));
        index = session->replay_cache->capacity - 1;
    } else {
        session->replay_cache->count++;
    }

    mr_replay_entry_t* entry = &session->replay_cache->entries[index];
    entry->message_id = message_id;
    entry->timestamp = time(NULL);
    memcpy(entry->message_hash, message_hash, SHA256_DIGEST_LENGTH);

    return MR_SUCCES;
}

uint64_t mr_generate_message_timestamp(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec;
}

int mr_verify_message_timestamp(mr_session_t* session, uint64_t message_timestamp) {
    if(!session || !session->replay_cache) {
        return MR_ERROR_INVALID_PARAM;
    }

    uint64_t current_time = time(NULL);
    uint64_t time_diff = current_time - message_timestamp;

    if(time_diff > session->replay_cache->window_seconds) {
        log_message(session->ctx, MR_LOG_WARN, "Message timestamp to old: %lu secconds", time_diff);
        return MR_ERROR_SESSION_EXPIRED;
    }

    if(message_timestamp > current_time + 60) {
        log_message(session->ctx, MR_LOG_WARN, "Message timestamp from future: %ld seconds", (long)(message_timestamp - current_time));
        return MR_ERROR_SEQUENCE;
    }

    return MR_SUCCESS;
}