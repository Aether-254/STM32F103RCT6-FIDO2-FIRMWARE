#ifndef KEY_OTP_SELFTEST_H
#define KEY_OTP_SELFTEST_H
#include "key_otp.h"
typedef struct {
    uint32_t magic, sequence, tested, passed, failed_case;
    int32_t error;
} key_otp_diagnostics;
extern KEY_CRYPTO_API volatile key_otp_diagnostics key_otp_snapshot;
/* Diagnostic only, public RFC vectors. No clock, provisioning or SD writes.
 * Even sequence = completed snapshot; failed_case is 1-based, zero if none.
 * Foreground service callback can keep USB responsive between test vectors.
 * Not an entropy test, certification, or proof of physical side-channel safety. */
KEY_CRYPTO_API void key_otp_selftest_run(void (*service)(void));
#endif
