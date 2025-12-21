#include <stdio.h>
#include <string.h>

uint8_t keys[16] = {0x2b,0x7e,0x15,0x16, 0xa1,0xb2,0xc3,0xd4,
                    0xf1,0xe2,0xd3,0xc4, 0x11,0x22,0x33,0x44};

void print_keys() {
    printf("Keys: %02x%02x%02x%02x...%02x%02x%02x%02x\n",
           keys[0],keys[1],keys[2],keys[3],keys[12],keys[13],keys[14],keys[15]);
}

void zeroize_keys() {
    memset(keys, 0, sizeof(keys));
}

int main() {
    printf("[SECURE] "); print_keys();
    printf("[ATTACK] Voltage glitch → zeroize\n");
    zeroize_keys();
    printf("[WIPED]  "); print_keys();
    return 0;
}
