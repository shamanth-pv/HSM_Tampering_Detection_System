#include "siem.h"
#include <stdio.h>

void siem_alert(const char* type, const char* hash) {
    printf("SIEM: {\"event\":\"%s\",\"fips\":\"L4\",\"hash\":\"%s\"}\n", type, hash);
}
