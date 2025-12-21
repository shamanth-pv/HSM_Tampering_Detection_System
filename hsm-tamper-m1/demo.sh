#!/bin/bash
echo "=== FIPS 140-3 Level 4 HSM Demo ==="
./build.sh
qemu-aarch64-static bin/tamper_level4
