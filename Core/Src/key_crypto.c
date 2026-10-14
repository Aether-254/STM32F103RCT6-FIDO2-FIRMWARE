#include "key_crypto.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/memory_buffer_alloc.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"
#include <stdbool.h>
#include <string.h>

_Alignas(8) static uint8_t crypto_arena[KEY_CRYPTO_ARENA_SIZE];
static bool initialized;
static const uint8_t empty=0;
enum { JOB_IDLE, JOB_RUNNING, JOB_DONE, JOB_FAILED };
static struct {
    mbedtls_ecdsa_context key;
    mbedtls_ecp_restart_ctx public_restart;
    mbedtls_ecdsa_restart_ctx sign_restart;
    uint8_t hash[32], output[72];
    size_t length;
    uint32_t owner;
    unsigned mode, state;
    bool contexts_initialized;
    key_crypto_random_fn random;
    void *random_context;
} job;

int key_crypto_init(void) {
    if (!initialized) {
        mbedtls_memory_buffer_alloc_init(crypto_arena,sizeof(crypto_arena));
        initialized=true;
    }
    return mbedtls_memory_buffer_alloc_verify()==0 ? 0 : KEY_CRYPTO_FAILED;
}
static bool buffer(const uint8_t *p, size_t n) { return (p || !n) && n<=KEY_CRYPTO_MAX_INPUT; }
static void wipe(uint8_t *p, size_t n) { if (p && n) mbedtls_platform_zeroize(p,n); }
int key_crypto_sha256(const uint8_t *p, size_t n, uint8_t hash[32]) {
    if (!hash) return KEY_CRYPTO_BAD_INPUT;
    if (!buffer(p,n)) { wipe(hash,32); return KEY_CRYPTO_BAD_INPUT; }
    int rc=mbedtls_sha256(p?p:&empty,n,hash,0);
    if (rc) wipe(hash,32);
    return rc ? KEY_CRYPTO_FAILED : 0;
}
int key_crypto_hkdf(const uint8_t key[32], const uint8_t *salt, size_t sn,
                    const uint8_t *info, size_t in, uint8_t derived[32]) {
    if (!derived) return KEY_CRYPTO_BAD_INPUT;
    if (!key || !buffer(salt,sn) || !buffer(info,in)) { wipe(derived,32); return KEY_CRYPTO_BAD_INPUT; }
    if (key_crypto_init()) { wipe(derived,32); return KEY_CRYPTO_FAILED; }
    int rc=mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                       salt?salt:&empty,sn,key,32,info?info:&empty,in,derived,32);
    if (rc) wipe(derived,32);
    return rc ? KEY_CRYPTO_FAILED : 0;
}
int key_crypto_hmac(const uint8_t key[32], const uint8_t *p, size_t n, uint8_t mac[32]) {
    if (!mac) return KEY_CRYPTO_BAD_INPUT;
    if (!key || !buffer(p,n)) { wipe(mac,32); return KEY_CRYPTO_BAD_INPUT; }
    if (key_crypto_init()) { wipe(mac,32); return KEY_CRYPTO_FAILED; }
    int rc=mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),key,32,
                          p?p:&empty,n,mac);
    if (rc) wipe(mac,32);
    return rc ? KEY_CRYPTO_FAILED : 0;
}
int key_crypto_seal(const uint8_t key[32], const uint8_t nonce[12],
                    const uint8_t *aad, size_t an, const uint8_t *p, size_t n,
                    uint8_t *c, size_t cap, uint8_t tag[16]) {
    if (!key || !nonce || !tag || !buffer(aad,an) || !buffer(p,n) ||
        (!c && n) || cap<n) {
        if (tag) wipe(tag,16);
        return KEY_CRYPTO_BAD_INPUT;
    }
    uint8_t dummy=0;
    mbedtls_chachapoly_context ctx; mbedtls_chachapoly_init(&ctx);
    int rc=mbedtls_chachapoly_setkey(&ctx,key);
    if (!rc) rc=mbedtls_chachapoly_encrypt_and_tag(&ctx,n,nonce,aad?aad:&empty,an,
                                                p?p:&empty,c?c:&dummy,tag);
    mbedtls_chachapoly_free(&ctx);
    if (rc) { wipe(c,n); wipe(tag,16); }
    return rc ? KEY_CRYPTO_FAILED : 0;
}
int key_crypto_open(const uint8_t key[32], const uint8_t nonce[12],
                    const uint8_t *aad, size_t an, const uint8_t tag[16],
                    const uint8_t *c, size_t n, uint8_t *p, size_t cap) {
    if (!key || !nonce || !tag || !buffer(aad,an) || !buffer(c,n) ||
        (!p && n) || cap<n) {
        /* No stale or partially authenticated plaintext survives a failure.
         * Only the caller-declared writable region may be cleared. */
        wipe(p,n<cap?n:cap); return KEY_CRYPTO_BAD_INPUT;
    }
    uint8_t dummy=0;
    mbedtls_chachapoly_context ctx; mbedtls_chachapoly_init(&ctx);
    int rc=mbedtls_chachapoly_setkey(&ctx,key);
    if (!rc) rc=mbedtls_chachapoly_auth_decrypt(&ctx,n,nonce,aad?aad:&empty,an,tag,
                                             c?c:&empty,p?p:&dummy);
    mbedtls_chachapoly_free(&ctx);
    if (rc) wipe(p,n);
    return rc ? KEY_CRYPTO_FAILED : 0;
}
int key_crypto_p256_public(const uint8_t priv[32], uint8_t pub[65],
                           key_crypto_random_fn random, void *random_context) {
    if (!pub) return KEY_CRYPTO_BAD_INPUT;
    wipe(pub,65);
    if (job.state!=JOB_IDLE) return KEY_CRYPTO_BUSY;
    if (!priv) return KEY_CRYPTO_BAD_INPUT;
    if (!random) return KEY_CRYPTO_NO_RANDOM;
    if (key_crypto_init()) return KEY_CRYPTO_FAILED;
    mbedtls_ecp_group g; mbedtls_ecp_group_init(&g);
    mbedtls_mpi d; mbedtls_mpi_init(&d);
    mbedtls_ecp_point q; mbedtls_ecp_point_init(&q);
    int rc=mbedtls_ecp_group_load(&g,MBEDTLS_ECP_DP_SECP256R1);
    if (!rc) rc=mbedtls_mpi_read_binary(&d,priv,32);
    if (!rc) rc=mbedtls_ecp_check_privkey(&g,&d);
    if (!rc) rc=mbedtls_ecp_mul(&g,&q,&d,&g.G,random,random_context);
    size_t used=0;
    if (!rc) rc=mbedtls_ecp_point_write_binary(&g,&q,MBEDTLS_ECP_PF_UNCOMPRESSED,&used,pub,65);
    mbedtls_ecp_point_free(&q); mbedtls_mpi_free(&d); mbedtls_ecp_group_free(&g);
    if (rc || used!=65 || key_crypto_init()) { wipe(pub,65); return KEY_CRYPTO_FAILED; }
    return 0;
}
int key_crypto_p256_sign(const uint8_t priv[32], const uint8_t hash[32],
                         uint8_t *sig, size_t cap, size_t *length,
                         key_crypto_random_fn random, void *random_context) {
    if (length) *length=0;
    if (sig && cap<=KEY_CRYPTO_MAX_INPUT) wipe(sig,cap);
    if (!length || !sig || !priv || !hash || cap<72 || cap>KEY_CRYPTO_MAX_INPUT)
        return KEY_CRYPTO_BAD_INPUT;
    if (job.state!=JOB_IDLE) return KEY_CRYPTO_BUSY;
    if (!random) return KEY_CRYPTO_NO_RANDOM;
    if (key_crypto_init()) return KEY_CRYPTO_FAILED;
    mbedtls_ecdsa_context ctx; mbedtls_ecdsa_init(&ctx);
    int rc=mbedtls_ecp_group_load(&ctx.MBEDTLS_PRIVATE(grp),MBEDTLS_ECP_DP_SECP256R1);
    if (!rc) rc=mbedtls_mpi_read_binary(&ctx.MBEDTLS_PRIVATE(d),priv,32);
    if (!rc) rc=mbedtls_ecp_check_privkey(&ctx.MBEDTLS_PRIVATE(grp),&ctx.MBEDTLS_PRIVATE(d));
    if (!rc) rc=mbedtls_ecdsa_write_signature(&ctx,MBEDTLS_MD_SHA256,hash,32,sig,cap,length,
                                             random,random_context);
    mbedtls_ecdsa_free(&ctx);
    if (rc || key_crypto_init()) { wipe(sig,cap); *length=0; return KEY_CRYPTO_FAILED; }
    return 0;
}
static void job_free_contexts(void) {
    if (!job.contexts_initialized) return;
    mbedtls_ecdsa_restart_free(&job.sign_restart);
    mbedtls_ecp_restart_free(&job.public_restart);
    mbedtls_ecdsa_free(&job.key);
    job.contexts_initialized=false;
    wipe(job.hash,sizeof(job.hash));
    job.random=NULL; job.random_context=NULL;
}
int key_crypto_job_cancel(uint32_t owner) {
    if (!owner || job.state==JOB_IDLE || owner!=job.owner) return KEY_CRYPTO_BAD_INPUT;
    job_free_contexts(); mbedtls_platform_zeroize(&job,sizeof(job));
    return key_crypto_init();
}
int key_crypto_job_begin(uint32_t owner, unsigned mode, const uint8_t priv[32],
    const uint8_t hash[32], key_crypto_random_fn random, void *context) {
    if (job.state!=JOB_IDLE) return KEY_CRYPTO_BUSY;
    if (!owner || !priv || (mode!=KEY_CRYPTO_JOB_PUBLIC && mode!=KEY_CRYPTO_JOB_SIGN) ||
        (mode==KEY_CRYPTO_JOB_SIGN && !hash)) return KEY_CRYPTO_BAD_INPUT;
    if (!random) return KEY_CRYPTO_NO_RANDOM;
    if (key_crypto_init()) return KEY_CRYPTO_FAILED;
    job.owner=owner; job.mode=mode; job.state=JOB_RUNNING;
    job.random=random; job.random_context=context;
    if (hash) memcpy(job.hash,hash,32);
    mbedtls_ecdsa_init(&job.key);
    mbedtls_ecp_restart_init(&job.public_restart);
    mbedtls_ecdsa_restart_init(&job.sign_restart); job.contexts_initialized=true;
    int rc=mbedtls_ecp_group_load(&job.key.MBEDTLS_PRIVATE(grp),MBEDTLS_ECP_DP_SECP256R1);
    if (!rc) rc=mbedtls_mpi_read_binary(&job.key.MBEDTLS_PRIVATE(d),priv,32);
    if (!rc) rc=mbedtls_ecp_check_privkey(&job.key.MBEDTLS_PRIVATE(grp),&job.key.MBEDTLS_PRIVATE(d));
    if (rc) { (void)key_crypto_job_cancel(owner); return KEY_CRYPTO_FAILED; }
    return 0;
}
int key_crypto_job_poll(uint32_t owner) {
    if (!owner || owner!=job.owner || job.state==JOB_IDLE) return KEY_CRYPTO_BAD_INPUT;
    if (job.state==JOB_DONE) return 0;
    if (job.state==JOB_FAILED) return KEY_CRYPTO_FAILED;
    mbedtls_ecp_set_max_ops(64); /* Cooperative budget; must profile on target. */
    int rc;
    if (job.mode==KEY_CRYPTO_JOB_PUBLIC) {
        rc=mbedtls_ecp_mul_restartable(&job.key.MBEDTLS_PRIVATE(grp),&job.key.MBEDTLS_PRIVATE(Q),
            &job.key.MBEDTLS_PRIVATE(d),&job.key.MBEDTLS_PRIVATE(grp).G,
            job.random,job.random_context,&job.public_restart);
        if (!rc) rc=mbedtls_ecp_point_write_binary(&job.key.MBEDTLS_PRIVATE(grp),
            &job.key.MBEDTLS_PRIVATE(Q),MBEDTLS_ECP_PF_UNCOMPRESSED,&job.length,job.output,65);
    } else {
        rc=mbedtls_ecdsa_write_signature_restartable(&job.key,MBEDTLS_MD_SHA256,job.hash,32,
            job.output,sizeof(job.output),&job.length,job.random,job.random_context,&job.sign_restart);
    }
    mbedtls_ecp_set_max_ops(0); /* Do not leak the global setting to other APIs. */
    if (rc==MBEDTLS_ERR_ECP_IN_PROGRESS) return KEY_CRYPTO_PENDING;
    job_free_contexts();
    if (rc || !job.length || job.length>72 ||
        (job.mode==KEY_CRYPTO_JOB_PUBLIC && job.length!=65) || key_crypto_init()) {
        wipe(job.output,sizeof(job.output)); job.length=0; job.state=JOB_FAILED;
        return KEY_CRYPTO_FAILED;
    }
    job.state=JOB_DONE; return 0;
}
int key_crypto_job_take(uint32_t owner, uint8_t *out, size_t cap, size_t *length) {
    if (length) *length=0;
    if (!length || !out || cap>KEY_CRYPTO_MAX_INPUT) return KEY_CRYPTO_BAD_INPUT;
    wipe(out,cap);
    if (!owner || owner!=job.owner || job.state!=JOB_DONE || cap<job.length)
        return KEY_CRYPTO_BAD_INPUT;
    memcpy(out,job.output,job.length); *length=job.length;
    int rc=key_crypto_job_cancel(owner);
    if (rc) { wipe(out,cap); *length=0; }
    return rc;
}
