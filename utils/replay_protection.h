#ifndef MESHRATCHET_REPLAY_PROTECTION_H
#define MESHRATCHET_REPLAY_PROTECTION_H

#include <cstdint>
#include <stdint.h>
#include "../include/meshratchet.h"

typedef struct {
    uint64_t message_id;
    uint64_t timestamp;
    uint64_t message_hash[32];
} mr_replay_entry_t;

typedef struct {
    mr_replay_entry_t* entries;
    size_t capacity;
    size_t count;
    uint32_t window_seconds;
} mr_replay_cache_t;

int mr_replay_protection_init(mr_session_t* session, size_t cache_size, uint32_t time_window_seconds);
void mr_replay_protection_cleanup(mr_session_t* session);
int mr_replay_check_and_add(mr_session_t* session, const uint8_t* message, size_t message_len, uint64_t message_id);
int mr_replay_is_message_seen(mr_session_t* session, const uint8_t message, size_t message_len);

int mr_verify_message_timestamp(mr_session_t* session, uint64_t mr_verify_message_timestamp);
uint64_t mr_generate_message_timestamp(void);

#endif