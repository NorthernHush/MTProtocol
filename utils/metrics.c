// utils/metrics.c
#include "metrics.h"
#include <string.h>
#include <time.h>
#include <stdio.h>  

// Подключаем внутренние структуры
#define MESHRATCHET_INTERNAL
#include "../include/meshratchet_internal.h"

int mr_metrics_init(mr_session_t* session) {
    if (!session) return MR_ERROR_INVALID_PARAM;
    
    // Инициализация метрик нулями
    memset(&session->metrics, 0, sizeof(session->metrics));
    session->avg_encrypt_time = 0.0;
    session->avg_decrypt_time = 0.0;
    
    return MR_SUCCESS;
}

int mr_metrics_update_encryption(mr_session_t* session, size_t data_len, double encrypt_time) {
    if (!session) return MR_ERROR_INVALID_PARAM;
    
    session->ctx->stats.total_messages_sent++;
    session->ctx->stats.total_bytes_encrypted += data_len;
    
    if (session->avg_encrypt_time == 0.0) {
        session->avg_encrypt_time = encrypt_time;
    } else {
        session->avg_encrypt_time = (session->avg_encrypt_time * 0.9) + (encrypt_time * 0.1);
    }
    
    return MR_SUCCESS;
}

int mr_metrics_update_decryption(mr_session_t* session, size_t data_len, double decrypt_time, int success) {
    if (!session) return MR_ERROR_INVALID_PARAM;
    
    session->ctx->stats.total_messages_received++;
    session->ctx->stats.total_bytes_decrypted += data_len;
    
    if (!success) {
        session->ctx->stats.errors_encountered++;
    }
    
    if (session->avg_decrypt_time == 0.0) {
        session->avg_decrypt_time = decrypt_time;
    } else {
        session->avg_decrypt_time = (session->avg_decrypt_time * 0.9) + (decrypt_time * 0.1);
    }
    
    return MR_SUCCESS;
}

mr_health_status_t mr_metrics_get_health_status(const mr_session_t* session) {
    if (!session) return MR_HEALTH_UNKNOWN;
    
    // Простая логика здоровья
    if (session->ctx->stats.errors_encountered > 100) {
        return MR_HEALTH_CRITICAL;
    } else if (session->ctx->stats.errors_encountered > 10) {
        return MR_HEALTH_WARNING;
    }
    return MR_HEALTH_GOOD;
}

int mr_metrics_get_detailed_report(const mr_session_t* session, char* report, size_t report_size) {
    if (!session || !report || report_size == 0) {
        return MR_ERROR_INVALID_PARAM;
    }
    
    int len = snprintf(report, report_size,
        "Session Metrics:\n"
        "  Messages Sent: %lu\n"
        "  Messages Received: %lu\n"
        "  Bytes Encrypted: %lu\n"
        "  Bytes Decrypted: %lu\n"
        "  Errors: %u\n"
        "  Avg Encrypt Time: %.2f ms\n"
        "  Avg Decrypt Time: %.2f ms\n",
        (unsigned long)session->ctx->stats.total_messages_sent,
        (unsigned long)session->ctx->stats.total_messages_received,
        (unsigned long)session->ctx->stats.total_bytes_encrypted,
        (unsigned long)session->ctx->stats.total_bytes_decrypted,
        session->ctx->stats.errors_encountered,
        session->avg_encrypt_time,
        session->avg_decrypt_time
    );
    
    return (len > 0 && (size_t)len < report_size) ? MR_SUCCESS : MR_ERROR_BUFFER_TOO_SMALL;
}