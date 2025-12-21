#ifndef AUDIT_LOG_H
#define AUDIT_LOG_H

#include <stdint.h>

void secure_log_event(uint32_t id, const char* type, const char* hash);

#endif
