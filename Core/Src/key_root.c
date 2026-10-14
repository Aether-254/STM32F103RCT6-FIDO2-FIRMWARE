#include "key_root.h"
#include <string.h>
static void wipe(void *p, size_t n) {
    volatile uint8_t *b = p;
    while (n--) *b++ = 0;
}
static int zero(const uint8_t *p, size_t n) {
    uint8_t v = 0;
    while (n--) v |= *p++;
    return v == 0;
}
int key_root_encode(const uint8_t root[32], const uint8_t device[12], uint8_t block[128]) {
    if (!block) return KEY_CRYPTO_BAD_INPUT;
    memset(block, 0, 128);
    if (!root || !device || zero(root, 32)) return KEY_CRYPTO_BAD_INPUT;
    memcpy(block, "F2RT", 4); block[4] = 1;
    memcpy(block+8, device, 12); memcpy(block+20, root, 32);
    if (key_crypto_sha256(block, 52, block+52)) { wipe(block, 128); return KEY_CRYPTO_FAILED; }
    block[126] = 0xA5; block[127] = 0x5A;
    return 0;
}
int key_root_decode(const uint8_t *block, size_t length, const uint8_t device[12], uint8_t root[32]) {
    uint8_t hash[32];
    if (!root) return KEY_CRYPTO_BAD_INPUT;
    wipe(root, 32);
    if (!block || length != 128 || !device || memcmp(block, "F2RT", 4) || block[4] != 1 ||
        !zero(block+5, 3) || memcmp(block+8, device, 12) || zero(block+20, 32) ||
        !zero(block+84, 42) || block[126] != 0xA5 || block[127] != 0x5A) return KEY_CRYPTO_BAD_INPUT;
    if (key_crypto_sha256(block, 52, hash)) { wipe(hash, 32); return KEY_CRYPTO_FAILED; }
    uint8_t difference = 0;
    for (unsigned i = 0; i < 32; ++i) difference |= hash[i] ^ block[52+i];
    wipe(hash, 32);
    if (difference) return KEY_CRYPTO_FAILED;
    memcpy(root, block+20, 32);
    return 0;
}
