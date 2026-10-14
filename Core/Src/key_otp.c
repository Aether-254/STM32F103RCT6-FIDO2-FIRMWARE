#include "key_otp.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"

static const mbedtls_md_info_t *digest(unsigned algorithm) {
    switch (algorithm) {
    case KEY_OTP_SHA1: return mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    case KEY_OTP_SHA256: return mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    case KEY_OTP_SHA512: return mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    default: return NULL;
    }
}

int key_otp_hotp(unsigned algorithm, unsigned digits,
    const uint8_t *secret, size_t length, uint64_t counter,
    char *output, size_t capacity) {
    if (output && capacity)
        mbedtls_platform_zeroize(output, capacity < KEY_OTP_CODE_SIZE ? capacity : KEY_OTP_CODE_SIZE);
    const mbedtls_md_info_t *md = digest(algorithm);
    if (!output || digits < 6 || digits > 8 || capacity < digits + 1 || !md ||
        !secret || length < KEY_OTP_SECRET_MIN || length > KEY_OTP_SECRET_MAX)
        return KEY_OTP_BAD_INPUT;
    if (key_crypto_init()) return KEY_OTP_CRYPTO_FAILED;
    uint8_t moving[8], mac[64] = {0};
    for (unsigned i = 0; i < 8; ++i)
        moving[i] = (uint8_t)(counter >> (56 - i * 8));
    int rc = mbedtls_md_hmac(md, secret, length, moving, sizeof(moving), mac);
    if (!rc) {
        unsigned offset = mac[mbedtls_md_get_size(md) - 1] & 15u;
        uint32_t value = ((uint32_t)(mac[offset] & 127u) << 24) |
            ((uint32_t)mac[offset + 1] << 16) |
            ((uint32_t)mac[offset + 2] << 8) | mac[offset + 3];
        uint32_t modulus = 1;
        for (unsigned i = 0; i < digits; ++i) modulus *= 10;
        value %= modulus;
        for (unsigned i = digits; i != 0; --i) {
            output[i - 1] = (char)('0' + value % 10);
            value /= 10;
        }
        output[digits] = '\0';
    }
    mbedtls_platform_zeroize(moving, sizeof(moving));
    mbedtls_platform_zeroize(mac, sizeof(mac));
    return rc ? KEY_OTP_CRYPTO_FAILED : 0;
}

int key_otp_totp(const key_otp_parameters *p, const uint8_t *secret,
    size_t length, uint64_t now, bool trusted, key_otp_view *view) {
    if (!view) return KEY_OTP_BAD_INPUT;
    mbedtls_platform_zeroize(view, sizeof(*view));
    if (!p || !p->period || p->period > 86400u || now < p->epoch)
        return KEY_OTP_BAD_INPUT;
    if (!trusted) return KEY_OTP_UNTRUSTED_TIME;
    uint64_t elapsed = now - p->epoch;
    view->counter = elapsed / p->period;
    view->remaining = p->period - (uint32_t)(elapsed % p->period);
    int rc = key_otp_hotp(p->algorithm, p->digits, secret, length,
        view->counter, view->current, sizeof(view->current));
    if (!rc && view->counter != UINT64_MAX) {
        rc = key_otp_hotp(p->algorithm, p->digits, secret, length,
            view->counter + 1, view->next, sizeof(view->next));
        view->next_valid = rc == 0;
    }
    if (rc) mbedtls_platform_zeroize(view, sizeof(*view));
    return rc;
}
