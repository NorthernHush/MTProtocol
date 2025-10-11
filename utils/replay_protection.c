#include "replay_protection.h"
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

mr_replay_cache_t* mr_replay_entry_create(size_t cache_size, uint64_t time_window_seconds) {
    mr_replay_cache_t* cache = calloc(1, sizeof(mr_replay_cache_t));
    if(!cache) return NULL;

    if(mr_replay_cache_init(cache, cache_size, time_window_seconds) != MR_SUCCESS) {
        free(cache);
        return NULL;
    }

    return cache;
}

int mr_replay_cache_init(mr_replay_cache_t* cache, size_t cache_size, uint64_t time_window_seconds) {
    if (!cache) return MR_ERROR_INVALID_PARAM;
    
    cache->entries = calloc(cache_size, sizeof(mr_replay_entry_t));
    if (!cache->entries) return MR_ERROR_MEMORY;
    
    cache->capacity = cache_size;
    cache->count = 0;
    cache->window_seconds = time_window_seconds;
    
    return MR_SUCCESS;
}

int mr_replay_check_and_add(mr_replay_cache_t* cache, const uint8_t* message_hash, size_t hash_len) {
    if (!cache || !message_hash || hash_len != SHA256_DIGEST_LENGTH) {
        return MR_ERROR_INVALID_PARAM;
    }

    // Проверка дубликатов
    for (size_t i = 0; i < cache->count; i++) {
        if (memcmp(cache->entries[i].message_hash, message_hash, SHA256_DIGEST_LENGTH) == 0) {
            return MR_ERROR_SEQUENCE; // replay detected
        }
    }

    // Управление размером кэша
    size_t index = cache->count;
    if (index >= cache->capacity) {
        // Сдвигаем окно: удаляем самый старый элемент
        memmove(cache->entries, cache->entries + 1, (cache->capacity - 1) * sizeof(mr_replay_entry_t));
        index = cache->capacity - 1;
    } else {
        cache->count++;
    }

    // Добавляем новую запись
    mr_replay_entry_t* entry = &cache->entries[index];
    memcpy(entry->message_hash, message_hash, SHA256_DIGEST_LENGTH);
    entry->timestamp = mr_generate_message_timestamp();

    return MR_SUCCESS;
}

uint64_t mr_generate_message_timestamp() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec;
}

int mr_verify_message_timestamp(uint64_t message_timestamp, uint64_t current_time, uint64_t window_seconds) {
    if (message_timestamp > current_time + window_seconds) {
        return MR_ERROR_VERIFICATION; // из будущего
    }
    if (current_time > message_timestamp + window_seconds) {
        return MR_ERROR_VERIFICATION; // слишком старое
    }
    return MR_SUCCESS;
}

void mr_replay_cache_cleanup(mr_replay_cache_t* cache) {
    if (cache && cache->entries) {
        free(cache->entries);
        cache->entries = NULL;
        cache->count = 0;
        cache->capacity = 0;
    }
}