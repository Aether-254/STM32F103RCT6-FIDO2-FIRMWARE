#ifndef KEY_OTP_H
#define KEY_OTP_H
#include "key_crypto.h"
#include <stdbool.h>
#define KEY_OTP_SHA1 1u
#define KEY_OTP_SHA256 2u
#define KEY_OTP_SHA512 3u
#define KEY_OTP_CODE_SIZE 9u
#define KEY_OTP_SECRET_MIN 16u
#define KEY_OTP_SECRET_MAX 128u
#define KEY_OTP_BAD_INPUT (-1)
#define KEY_OTP_UNTRUSTED_TIME (-2)
#define KEY_OTP_CRYPTO_FAILED (-3)
typedef struct {
    uint32_t algorithm, digits, period;
    uint64_t epoch;
} key_otp_parameters;
typedef struct {
    uint64_t counter;
    uint32_t remaining;
    char current[KEY_OTP_CODE_SIZE], next[KEY_OTP_CODE_SIZE];
    bool next_valid;
} key_otp_view;
/* Foreground only. No storage, clock reads, secret generation or authorization.
 * Secret/output buffers must not overlap. Secrets are caller-owned binary bytes.
 * SHA1/256/512, 6..8 digits, 16..128B keys. Extra SHA2 HOTP is an extension.
 * HOTP is calculation only: caller must durably reserve/commit the counter
 * BEFORE displaying a code. Calling this function never advances a counter.
 * Output needs digits+1 bytes; errors clear up to min(capacity,9) writable bytes. */
KEY_CRYPTO_API int key_otp_hotp(unsigned algorithm, unsigned digits,
    const uint8_t *secret, size_t length, uint64_t counter,
    char *output, size_t capacity);
/* Uses explicit UTC Unix seconds, never HAL tick or local-time text.
 * Rejects untrusted time and now<epoch; period is 1..86400 seconds.
 * remaining is 1..period (full period at a boundary). next_valid is false
 * at UINT64_MAX counter, rather than wrapping. Every error zeroes the view.
 * Caller must enforce secret access authorization and wipe the view on lock. */
KEY_CRYPTO_API int key_otp_totp(const key_otp_parameters *parameters,
    const uint8_t *secret, size_t length, uint64_t now, bool time_trusted,
    key_otp_view *view);
#endif
