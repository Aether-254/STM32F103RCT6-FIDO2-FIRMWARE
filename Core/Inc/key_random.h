#ifndef KEY_RANDOM_H
#define KEY_RANDOM_H
#include "key_journal.h"
#define KEY_RANDOM_MAX_REQUEST 1024u
#define KEY_RANDOM_MAX_CALLS 65536u
/* Serialized foreground singleton. NO default RNG, no UID/time/ADC entropy.
 * Boot reserves one durable nonce before HKDF(root,device,domain+epoch) seeds
 * Mbed TLS HMAC-DRBG. Trusted 256-bit root entropy is externally provisioned;
 * changing public epoch does not add fresh physical entropy. This is a project
 * deterministic-root construction, not a certified NIST/FIDO entropy source.
 * Start/stop must not race a crypto job or backend using this callback. */
KEY_CRYPTO_API int key_random_boot(key_journal *, const uint8_t root[32], const uint8_t device[12]);
KEY_CRYPTO_API bool key_random_ready(void);
KEY_CRYPTO_API bool key_random_bound(const key_journal *);
KEY_CRYPTO_API uint64_t key_random_epoch(void);
KEY_CRYPTO_API uint32_t key_random_remaining(void);
/* Compatible key_crypto_random_fn; context ignored. Max 1024B per request.
 * On error, bounded valid-size output is wiped; invalid oversized requests
 * touch no memory. Quota exhaustion disables generator, never silently reseeds.
 * Output buffer must be caller-owned, disjoint from internal/provider state. */
KEY_CRYPTO_API int key_random_bytes(void *, unsigned char *, size_t);
/* Unbiased rejection sampling of a nonzero scalar below P-256 order, bounded
 * to 16 attempts. No reduction modulo order or fixed test private key. */
KEY_CRYPTO_API int key_random_private(uint8_t private_key[32]);
KEY_CRYPTO_API void key_random_stop(void);
#endif
