#ifndef REPLAY_PROTECTION_H
#define REPLAY_PROTECTION_H

#include <stdint.h>
#include <stddef.h>
#include "../include/meshratchet.h"

#define SHA256_DIGEST_LENGTH 32

typedef struct {
    uint8_t message_hash[SHA256_DIGEST_LENGTH];
    uint64_t timestamp;
} mr_replay_entry_t;

typedef struct {
    mr_replay_entry_t* entries;
    size_t capacity;
    size_t count;
    uint64_t window_seconds;
} mr_replay_cache_t;

// Создание нового кэша
mr_replay_cache_t* mr_replay_cache_create(size_t cache_size, uint64_t time_window_seconds);

// Инициализация кэша
int mr_replay_cache_init(mr_replay_cache_t* cache, size_t cache_size, uint64_t time_window_seconds);

// Проверка и добавление сообщения
int mr_replay_check_and_add(mr_replay_cache_t* cache, const uint8_t* message_hash, size_t hash_len);

// Генерация временной метки
uint64_t mr_generate_message_timestamp();

// Проверка временной метки
int mr_verify_message_timestamp(uint64_t message_timestamp, uint64_t current_time, uint64_t window_seconds);

// Очистка кэша
void mr_replay_cache_cleanup(mr_replay_cache_t* cache);

#endif