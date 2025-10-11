// utils/metrics.h
#ifndef METRICS_H
#define METRICS_H

#include "../include/meshratchet.h"

int mr_metrics_init(mr_session_t* session);
int mr_metrics_update_encryption(mr_session_t* session, size_t data_len, double encrypt_time);
int mr_metrics_update_decryption(mr_session_t* session, size_t data_len, double decrypt_time, int success);
mr_health_status_t mr_metrics_get_health_status(const mr_session_t* session);
int mr_metrics_get_detailed_report(const mr_session_t* session, char* report, size_t report_size);

#endif