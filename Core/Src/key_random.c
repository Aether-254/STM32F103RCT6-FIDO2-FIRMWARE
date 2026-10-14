#include "key_random.h"
#include "mbedtls/hmac_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"
#include <string.h>

static mbedtls_hmac_drbg_context drbg;
static bool active, context_initialized;
static uint32_t calls;
static uint64_t epoch;
static const key_journal *owner;
void key_random_stop(void) {
    if (context_initialized) mbedtls_hmac_drbg_free(&drbg);
    mbedtls_platform_zeroize(&drbg, sizeof(drbg));
    active = false; context_initialized = false; calls = 0; epoch = 0; owner = NULL;
}
bool key_random_ready(void) { return active && calls < KEY_RANDOM_MAX_CALLS; }
bool key_random_bound(const key_journal *journal) {
    return key_random_ready() && owner == journal && journal && journal->ready;
}
uint64_t key_random_epoch(void) { return active ? epoch : 0; }
uint32_t key_random_remaining(void) { return active ? KEY_RANDOM_MAX_CALLS-calls : 0; }
int key_random_boot(key_journal *journal, const uint8_t root[32], const uint8_t device[12]) {
    static const uint8_t domain[] = "stm32-fido2/boot-drbg/v1";
    uint8_t info[sizeof(domain)-1+8], seed[32];
    uint64_t reserved = 0; uint32_t unused = 0;
    if (active) return KEY_CRYPTO_BUSY;
    if (!key_journal_matches(journal, root, device)) return KEY_CRYPTO_NO_RANDOM;
    /* This consumes a journal nonce, separate from future credential ranges.
     * Any later failure burns it. Never issue random bytes before reservation. */
    if (key_journal_reserve(journal, 1, 0, &reserved, &unused)) return KEY_CRYPTO_NO_RANDOM;
    memcpy(info, domain, sizeof(domain)-1);
    for (unsigned i = 0; i < 8; ++i) info[sizeof(domain)-1+i] = (uint8_t)(reserved >> (56-8*i));
    int rc = key_crypto_hkdf(root, device, 12, info, sizeof(info), seed);
    if (!rc) {
        mbedtls_hmac_drbg_init(&drbg); context_initialized = true;
        rc = mbedtls_hmac_drbg_seed_buf(&drbg, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), seed, 32);
    }
    mbedtls_platform_zeroize(seed, sizeof(seed));
    mbedtls_platform_zeroize(info, sizeof(info));
    if (rc) { key_random_stop(); return KEY_CRYPTO_FAILED; }
    /* seed_buf provides no entropy callback. Explicit wrapper quota prevents
     * unbounded generation and forces a new durable epoch instead of fallback. */
    calls = 0; epoch = reserved; owner = journal; active = true;
    return 0;
}
int key_random_bytes(void *context, unsigned char *out, size_t length) {
    (void)context;
    if ((!out && length) || length > KEY_RANDOM_MAX_REQUEST) return KEY_CRYPTO_BAD_INPUT;
    if (!key_random_ready()) {
        if (out && length) mbedtls_platform_zeroize(out, length);
        if (active) key_random_stop();
        return KEY_CRYPTO_NO_RANDOM;
    }
    if (!length) return 0; /* Empty requests neither advance nor consume quota. */
    if (mbedtls_hmac_drbg_random(&drbg, out, length)) {
        mbedtls_platform_zeroize(out, length); key_random_stop(); return KEY_CRYPTO_FAILED;
    }
    ++calls;
    return 0;
}
static int private_from(key_crypto_random_fn random, void *context, uint8_t out[32]) {
    static const uint8_t order[32] = {
        0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xBC,0xE6,0xFA,0xAD,0xA7,0x17,0x9E,0x84,0xF3,0xB9,0xCA,0xC2,0xFC,0x63,0x25,0x51};
    if (!out) return KEY_CRYPTO_BAD_INPUT;
    if (!random) { mbedtls_platform_zeroize(out, 32); return KEY_CRYPTO_NO_RANDOM; }
    for (unsigned tries = 0; tries < 16; ++tries) {
        int rc = random(context, out, 32);
        if (rc) { mbedtls_platform_zeroize(out, 32); return KEY_CRYPTO_NO_RANDOM; }
        uint8_t nonzero = 0;
        for (unsigned i = 0; i < 32; ++i) nonzero |= out[i];
        if (nonzero && memcmp(out, order, 32) < 0) return 0;
    }
    mbedtls_platform_zeroize(out, 32); return KEY_CRYPTO_FAILED;
}
int key_random_private(uint8_t out[32]) {
    int rc = private_from(key_random_bytes, NULL, out);
    if (rc == KEY_CRYPTO_FAILED) key_random_stop();
    return rc;
}
#ifdef KEY_CRYPTO_HOST_TEST
/* Test-only entry point for infeasible rejection branches. Same helper as
 * production; NOT declared in production headers or present in target ELF. */
KEY_CRYPTO_API int key_random_test_private(key_crypto_random_fn random, void *context, uint8_t out[32]) {
    return private_from(random, context, out);
}
#endif
