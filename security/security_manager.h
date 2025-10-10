#ifndef MESHRATCHET_SECURITY_MANAGER_H
#define MESHRATCHET_SECURITY_MANAGER_H

#include "../include/meshratchet.h"
#include <time.h>


typedef enum {
    MR_SECURITY_LOW = 1,      
    MR_SECURITY_MEDIUM = 3,   
    MR_SECURITY_HIGH = 5,    
    MR_SECURITY_PARANOID = 8  /
} mr_security_level_t;


typedef struct {
    mr_security_level_t level;
    int enable_replay_protection;
    int enable_message_auth;
    int enable_timestamps;
    int enable_forward_secrecy;
    uint32_t key_rotation_interval;
    uint32_t max_message_age;
    size_t replay_cache_size;
} mr_security_config_t;


typedef struct {
    mr_security_config_t config;
    uint32_t security_events;
    uint32_t attacks_blocked;
    time_t last_security_audit;
} mr_security_manager_t;


int mr_security_init(mr_session_t* session, mr_security_level_t level);
int mr_security_apply_config(mr_session_t* session, const mr_security_config_t* config);
int mr_security_audit_session(mr_session_t* session);
int mr_security_detect_anomalies(mr_session_t* session);

#endif