#!/bin/bash
set -e
mkdir -p bin logs
aarch64-linux-gnu-gcc -Wall -std=c99 -Ihal -Icore -Imonitor \
    hal/sim_hal.c core/tamper_core.c core/audit_log.c monitor/siem.c src/main.c \
    -o bin/tamper_level4 -static
echo "✓ ARM64 Production Binary: $(file bin/tamper_level4)"
echo "Demo: qemu-aarch64-static bin/tamper_level4"
echo "Logs: cat logs/audit.jsonl"
