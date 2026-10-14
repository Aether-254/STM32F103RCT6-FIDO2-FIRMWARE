#include "key_vault.h"
#include <string.h>

#define HEADER_SIZE 32u
#define PLAIN_SIZE 464u
#define AAD_SIZE (HEADER_SIZE + 32u + 2u + 256u)
static const uint8_t domain[] = "stm32-fido2/credential-record/v1";
static void wipe(void *p, size_t n) {
    volatile uint8_t *b = (volatile uint8_t *)p;
    while (n--) *b++ = 0;
}
static int zero(const uint8_t *p, size_t n) {
    uint8_t v = 0;
    while (n--) v |= *p++;
    return v == 0;
}
static int shape(const ctap_credential_record *r) {
    return r && r->id_length && r->id_length <= 256 &&
        r->user_length && r->user_length <= 64 && !zero(r->private_key, 32);
}
static size_t aad_make(uint8_t *aad, const uint8_t *header,
    const uint8_t *rp, const uint8_t *id, size_t length) {
    memcpy(aad, header, HEADER_SIZE);
    memcpy(aad + HEADER_SIZE, rp, 32);
    aad[64] = (uint8_t)(length >> 8);
    aad[65] = (uint8_t)length;
    memcpy(aad + 66, id, length);
    return 66 + length;
}
static int derive(const uint8_t *root, const uint8_t *context, uint8_t *key) {
    return key_crypto_hkdf(root, context, 12, domain, sizeof(domain)-1, key);
}
int key_vault_seal(const uint8_t root[32], const uint8_t context[12],
    uint64_t sequence, const ctap_credential_record *record, uint8_t block[512]) {
    uint8_t plain[PLAIN_SIZE] = {0}, aad[AAD_SIZE], key[32] = {0};
    int result = KEY_VAULT_BAD_INPUT;
    if (!block) return result;
    memset(block, 0, 512);
    if (!root || !context || !sequence || zero(root, 32) || !shape(record)) goto done;
    memcpy(block, "F2CR", 4);
    block[4] = 1;
    block[5] = 1;
    for (unsigned i = 0; i < 8; ++i) block[8+i] = (uint8_t)(sequence >> (56-8*i));
    memcpy(block + 16, "CRED", 4);
    memcpy(block + 20, block + 8, 8);
    memcpy(plain, record->private_key, 32);
    memcpy(plain + 32, record->rp_hash, 32);
    plain[64] = (uint8_t)(record->id_length >> 8);
    plain[65] = (uint8_t)record->id_length;
    plain[66] = (uint8_t)record->user_length;
    memcpy(plain + 68, record->id, record->id_length);
    memcpy(plain + 324, record->user_id, record->user_length);
    size_t aad_length = aad_make(aad, block, record->rp_hash, record->id, record->id_length);
    result = KEY_VAULT_CRYPTO_FAILED;
    if (derive(root, context, key) != 0) goto done;
    if (key_crypto_seal(key, block+16, aad, aad_length, plain, sizeof(plain),
                        block+32, PLAIN_SIZE, block+496) == 0) result = 0;
done:
    wipe(plain, sizeof(plain));
    wipe(key, sizeof(key));
    wipe(aad, sizeof(aad));
    if (result) wipe(block, 512);
    return result;
}
int key_vault_open(const uint8_t root[32], const uint8_t context[12],
    const uint8_t expected_rp[32], const uint8_t *expected_id, size_t id_length,
    const uint8_t *block, size_t block_length, ctap_credential_record *record) {
    uint8_t plain[PLAIN_SIZE] = {0}, aad[AAD_SIZE], key[32] = {0};
    int result = KEY_VAULT_BAD_INPUT;
    if (!record) return result;
    memset(record, 0, sizeof(*record));
    if (!root || !context || zero(root, 32) || !expected_rp || !expected_id ||
        !id_length || id_length > 256 || !block || block_length != 512) goto done;
    if (memcmp(block, "F2CR", 4) || block[4] != 1 || block[5] != 1 ||
        !zero(block+6, 2) || !zero(block+28, 4) || zero(block+8, 8) ||
        memcmp(block+16, "CRED", 4) || memcmp(block+20, block+8, 8)) goto done;
    size_t aad_length = aad_make(aad, block, expected_rp, expected_id, id_length);
    result = KEY_VAULT_CRYPTO_FAILED;
    if (derive(root, context, key) != 0) goto done;
    result = KEY_VAULT_AUTH_FAILED;
    if (key_crypto_open(key, block+16, aad, aad_length, block+496,
                        block+32, PLAIN_SIZE, plain, sizeof(plain)) != 0) goto done;
    size_t stored_length = ((size_t)plain[64] << 8) | plain[65];
    size_t user_length = plain[66];
    if (stored_length != id_length || !user_length || user_length > 64 ||
        plain[67] || zero(plain, 32) || memcmp(plain+32, expected_rp, 32) ||
        memcmp(plain+68, expected_id, id_length) ||
        !zero(plain+68+id_length, 256-id_length) ||
        !zero(plain+324+user_length, 64-user_length) || !zero(plain+388, 76)) goto done;
    memcpy(record->private_key, plain, 32);
    memcpy(record->rp_hash, plain+32, 32);
    memcpy(record->id, plain+68, id_length);
    memcpy(record->user_id, plain+324, user_length);
    record->id_length = id_length;
    record->user_length = user_length;
    result = 0;
done:
    wipe(plain, sizeof(plain));
    wipe(key, sizeof(key));
    wipe(aad, sizeof(aad));
    return result;
}
