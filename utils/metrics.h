#ifndef MESHRATCHET_METRICS_H
#define MESHRATCHET_METRICS_H

#include "../include/meshratchet.h"
#include <time.h>

typedef struct {
    uint64_t total_encrypted_bytes;
    uint64_t total_decrypted_bytes;
    uint32_t messages_sent;
    uint32_t messages_received;
    uint32_t failed_decryptions;
    uint32_t key_rotations;
    uint32_t quantum_updates;
    uint32_t out_of_order_sequences;
    
    double min_encrypt_time_ms;
    double max_encrypt_time_ms;
    double avg_encrypt_time_ms;
    double avg_decrypt_time_ms;
    
    uint32_t security_events;
    uint32_t potential_attacks_detected;
    uint32_t key_exhaustion_warnings;
    
    time_t session_start_time;
    time_t last_security_event;
    uint32_t uptime_seconds;
} mr_session_metrics_t;

typedef enum {
    MR_HEALTH_EXCELLENT = 0,
    MR_HEALTH_GOOD = 1,
    MR_HEALTH_DEGRADED = 2,
    MR_HEALTH_POOR = 3,
    MR_HEALTH_CRITICAL = 4
} mr_health_status_t;

int mr_metrics_init(mr_session_t* session);
int mr_metrics_update_encryption(mr_session_t* session, size_t data_len, double encrypt_time);
int mr_metrics_update_decryption(mr_session_t* session, size_t data_len, double decrypt_time, int success);
mr_health_status_t mr_metrics_get_health_status(const mr_session_t* session);
int mr_metrics_get_detailed_report(const mr_session_t* session, char* report, size_t report_size);

#endif