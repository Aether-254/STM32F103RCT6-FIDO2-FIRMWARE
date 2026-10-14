#include "key_otp_selftest.h"
#include "mbedtls/platform_util.h"
#include <string.h>
volatile key_otp_diagnostics key_otp_snapshot;
static const struct {
    uint64_t now;
    char expected[3][9];
} vectors[] = {
    {59, {"94287082", "46119246", "90693936"}},
    {1111111109, {"07081804", "68084774", "25091201"}},
    {1111111111, {"14050471", "67062674", "99943326"}},
    {1234567890, {"89005924", "91819424", "93441116"}},
    {2000000000, {"69279037", "90698825", "38618901"}},
    {UINT64_C(20000000000), {"65353130", "77737706", "47863826"}}
};
/* Deliberately public standard fixture; never import into a user's account. */
static const uint8_t secret[] =
    "1234567890123456789012345678901234567890123456789012345678901234";
void key_otp_selftest_run(void (*service)(void)) {
    key_otp_snapshot.magic = 0;
    key_otp_snapshot.sequence = 1;
    key_otp_snapshot.tested = key_otp_snapshot.passed = 0;
    key_otp_snapshot.failed_case = 0;
    key_otp_snapshot.error = 0;
    for (unsigned i = 0; i < sizeof(vectors) / sizeof(vectors[0]); ++i) {
        for (unsigned alg = 1; alg <= 3; ++alg) {
            key_otp_parameters p = {alg, 8, 30, 0};
            key_otp_view view;
            size_t n = alg == 1 ? 20 : (alg == 2 ? 32 : 64);
            int rc = key_otp_totp(&p, secret, n, vectors[i].now, true, &view);
            ++key_otp_snapshot.tested;
            bool pass = !rc && !memcmp(view.current, vectors[i].expected[alg - 1], 9) &&
                view.counter == vectors[i].now / 30 &&
                view.remaining == 30 - vectors[i].now % 30 && view.next_valid;
            if (pass) ++key_otp_snapshot.passed;
            else if (!key_otp_snapshot.failed_case) {
                key_otp_snapshot.failed_case = key_otp_snapshot.tested;
                key_otp_snapshot.error = rc ? rc : KEY_OTP_CRYPTO_FAILED;
            }
            mbedtls_platform_zeroize(&view, sizeof(view));
            if (service) service();
        }
    }
    key_otp_snapshot.magic = 0x4F545031u;
    key_otp_snapshot.sequence = 2;
}
