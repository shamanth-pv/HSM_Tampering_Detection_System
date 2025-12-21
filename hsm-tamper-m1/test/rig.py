#!/usr/bin/env python3
import subprocess, json

print("=== FIPS L4 Test Rig ===")
result = subprocess.run(["../bin/tamper_level4"], capture_output=True, text=True)
print("Test Rig: PASS ✓" if "ALL TESTS PASS" in result.stdout else "FAIL")
print("Audit Log:")
with open("../logs/audit.jsonl") as f:
    print(f.read()[-200:])
