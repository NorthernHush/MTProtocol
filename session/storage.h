#ifndef MESHRATCHET_STORAGE_H
#define MESHRATCHET_STORAGE_H

#include "../include/meshratchet.h"
#include <stdint.h>

typedef struct {
    uint8_t version;
    uint8_t session_data[512];
    uint32_t crc32;
} mr_serialized_session_t;


size_t mr_storage_get_session_size(const mr_session_t* session);
int mr_storage_serialize_session(const mr_session_t* session, uint8_t* buffer, size_t buffer_len);
mr_session_t* mr_storage_deserialize_session(mr_ctx_t* ctx, const uint8_t* data, size_t data_len);

int mr_storage_save_session(const mr_session_t* session, const char* filename);
mr_session_t* mr_storage_load_session(mr_ctx_t* ctx, const char* filename);

int mr_storage_upgrade_session(mr_session_t* session, uint32_t from_version);

int mr_session_serialize(mr_session_t* session, uint8_t* out, size_t* len);
mr_session_t* mr_session_deserialize(mr_ctx_t* ctx, const uint8_t* data, size_t len);

#endif