#include "key_authdata.h"
#include <string.h>
#include "mbedtls/platform_util.h"
static void count(uint8_t *p, uint32_t n) {
    p[0]=(uint8_t)(n>>24); p[1]=(uint8_t)(n>>16); p[2]=(uint8_t)(n>>8); p[3]=(uint8_t)n;
}
static int rp_hash(const uint8_t *rp, size_t n, uint8_t hash[32]) {
    if (!rp || !n || n>253 || memchr(rp,0,n)) return KEY_CRYPTO_BAD_INPUT;
    return key_crypto_sha256(rp,n,hash);
}
int key_authdata_assert(const uint8_t *rp, size_t n, uint32_t counter, bool up,
                        uint8_t *out, size_t cap) {
    if (!out || cap<37) return KEY_CRYPTO_BAD_INPUT;
    memset(out,0,37);
    int rc=rp_hash(rp,n,out); if (rc) return rc;
    out[32]=up?1:0; count(out+33,counter); return 0;
}
int key_authdata_from_public(const uint8_t *rp, size_t n, const uint8_t pub[65],
    const uint8_t *id, size_t idlen, uint32_t counter, uint8_t *out, size_t cap, size_t *length) {
    if (length) *length=0;
    if (!length || !out || !pub || pub[0]!=4 || !id || !idlen || idlen>256 || cap<132+idlen)
        return KEY_CRYPTO_BAD_INPUT;
    memset(out,0,132+idlen);
    int rc=rp_hash(rp,n,out); if (rc) return rc;
    out[32]=0x41; count(out+33,counter); /* UP and AT, never UV. */
    /* Zero engineering AAGUID at 37..52, not a vendor identity. */
    out[53]=(uint8_t)(idlen>>8); out[54]=(uint8_t)idlen;
    memcpy(out+55,id,idlen);
    uint8_t *cose=out+55+idlen;
    /* Canonical COSE EC2: {1:2,3:-7,-1:1,-2:x,-3:y}. */
    const uint8_t prefix[]={0xa5,0x01,0x02,0x03,0x26,0x20,0x01,0x21,0x58,0x20};
    memcpy(cose,prefix,sizeof(prefix)); memcpy(cose+10,pub+1,32);
    cose[42]=0x22; cose[43]=0x58; cose[44]=0x20; memcpy(cose+45,pub+33,32);
    *length=132+idlen; return 0;
}
int key_authdata_make(const uint8_t *rp, size_t n, const uint8_t priv[32],
    const uint8_t *id, size_t idlen, uint32_t counter, uint8_t *out, size_t cap,
    size_t *length, key_crypto_random_fn random, void *context) {
    if (length) *length=0;
    if (!length || !out || !priv || !id || !idlen || idlen>256 || cap<132+idlen)
        return KEY_CRYPTO_BAD_INPUT;
    uint8_t pub[65];
    int rc=key_crypto_p256_public(priv,pub,random,context);
    if (!rc) rc=key_authdata_from_public(rp,n,pub,id,idlen,counter,out,cap,length);
    if (rc) mbedtls_platform_zeroize(out,132+idlen);
    mbedtls_platform_zeroize(pub,sizeof(pub)); return rc;
}
int key_authdata_digest(const uint8_t *data, size_t n, const uint8_t cdh[32], uint8_t digest[32]) {
    if (!data || n<37 || n>KEY_AUTHDATA_MAX_SIZE || !cdh || !digest) return KEY_CRYPTO_BAD_INPUT;
    uint8_t preimage[KEY_AUTHDATA_MAX_SIZE+32];
    memcpy(preimage,data,n); memcpy(preimage+n,cdh,32);
    int rc=key_crypto_sha256(preimage,n+32,digest);
    mbedtls_platform_zeroize(preimage,sizeof(preimage)); return rc;
}
