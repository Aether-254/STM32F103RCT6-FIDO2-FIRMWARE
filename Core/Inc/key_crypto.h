#ifndef KEY_CRYPTO_H
#define KEY_CRYPTO_H
#include <stddef.h>
#include <stdint.h>
#define KEY_CRYPTO_MAX_INPUT 4096u
#define KEY_CRYPTO_ARENA_SIZE 16384u
#define KEY_CRYPTO_BAD_INPUT (-1)
#define KEY_CRYPTO_NO_RANDOM (-2)
#define KEY_CRYPTO_FAILED (-3)
#define KEY_CRYPTO_BUSY (-4)
#define KEY_CRYPTO_PENDING 1
#define KEY_CRYPTO_JOB_PUBLIC 1u
#define KEY_CRYPTO_JOB_SIGN 2u
typedef int (*key_crypto_random_fn)(void *, unsigned char *, size_t);
#if defined(KEY_CRYPTO_HOST_TEST) && defined(_WIN32)
#define KEY_CRYPTO_API __declspec(dllexport)
#else
#define KEY_CRYPTO_API
#endif
/* Foreground-only, serialized API. No implicit entropy, no key generation,
 * no persistence and no hardware provisioning are performed by this layer. */
KEY_CRYPTO_API int key_crypto_init(void);
KEY_CRYPTO_API int key_crypto_sha256(const uint8_t *input, size_t length, uint8_t hash[32]);
KEY_CRYPTO_API int key_crypto_hmac(const uint8_t key[32], const uint8_t *input,
                                 size_t length, uint8_t mac[32]);
KEY_CRYPTO_API int key_crypto_hkdf(const uint8_t key[32], const uint8_t *salt, size_t salt_length,
                    const uint8_t *info, size_t info_length, uint8_t derived[32]);
KEY_CRYPTO_API int key_crypto_seal(const uint8_t key[32], const uint8_t nonce[12],
                    const uint8_t *aad, size_t aad_length,
                    const uint8_t *plaintext, size_t length,
                    uint8_t *ciphertext, size_t capacity, uint8_t tag[16]);
KEY_CRYPTO_API int key_crypto_open(const uint8_t key[32], const uint8_t nonce[12],
                    const uint8_t *aad, size_t aad_length, const uint8_t tag[16],
                    const uint8_t *ciphertext, size_t length,
                    uint8_t *plaintext, size_t capacity);
/* Input private scalar is caller-owned, explicitly supplied; this API never
 * derives one from UID/time. Blinding RNG is mandatory, even with RFC6979. */
KEY_CRYPTO_API int key_crypto_p256_public(const uint8_t private_key[32], uint8_t public_key[65],
                           key_crypto_random_fn random, void *random_context);
KEY_CRYPTO_API int key_crypto_p256_sign(const uint8_t private_key[32], const uint8_t hash[32],
                         uint8_t *signature, size_t capacity, size_t *length,
                         key_crypto_random_fn random, void *random_context);
/* One serialized restartable ECC job. Owner must be a fresh nonzero generation;
 * stale owner calls cannot progress/cancel/take another request. Inputs copied
 * at begin; random callback/context must remain valid until completion/cancel.
 * poll returns PENDING, 0=complete, negative=failure. No partial output exposed.
 * take returns one public key (65B) or DER signature (<=72B), then wipes job.
 * Failed jobs must be cancelled before reuse. max_ops is not a time guarantee. */
KEY_CRYPTO_API int key_crypto_job_begin(uint32_t owner, unsigned mode,
    const uint8_t private_key[32], const uint8_t hash[32],
    key_crypto_random_fn random, void *random_context);
KEY_CRYPTO_API int key_crypto_job_poll(uint32_t owner);
KEY_CRYPTO_API int key_crypto_job_take(uint32_t owner, uint8_t *output, size_t capacity, size_t *length);
KEY_CRYPTO_API int key_crypto_job_cancel(uint32_t owner);
#endif
