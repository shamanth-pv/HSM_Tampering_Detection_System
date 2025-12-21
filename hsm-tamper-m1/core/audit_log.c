#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void secure_log_event(uint32_t id, const char* type, const char* hash) {
    FILE *log = fopen("logs/audit.jsonl", "a");
    if (log) {
        fprintf(log, "{\"id\":%u,\"type\":\"%s\",\"hash\":\"%s\"}\n", id, type, hash);
        fclose(log);
    }
}
