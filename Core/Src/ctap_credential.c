#include "ctap_credential.h"
#include "ctap_dispatch.h"
#include "mbedtls/platform_util.h"
#include <string.h>
enum { IDLE, SELECT, WAIT_UP, CREATE, PUBLIC, COMMIT, COUNTER, SIGN };
static uint32_t next_generation;
uint32_t ctap_credential_presence_progress(const ctap_credential_engine *e, uint32_t now) {
    return e && e->phase==WAIT_UP ? key_presence_progress(&e->presence,now) : 0;
}
typedef struct { uint8_t *out; size_t used, capacity; bool failed; } writer;
static void put(writer *w, const void *p, size_t n) {
    if (w->failed || n>w->capacity-w->used) { w->failed=true; return; }
    memcpy(w->out+w->used,p,n); w->used+=n;
}
static void byte(writer *w, uint8_t b) { put(w,&b,1); }
static void head(writer *w, unsigned major, size_t n) {
    if (n<24) byte(w,(uint8_t)((major<<5)|n));
    else if (n<256) { byte(w,(uint8_t)((major<<5)|24)); byte(w,(uint8_t)n); }
    else { byte(w,(uint8_t)((major<<5)|25)); byte(w,(uint8_t)(n>>8)); byte(w,(uint8_t)n); }
}
static void blob(writer *w, unsigned major, const void *p, size_t n) { head(w,major,n); put(w,p,n); }
static void text(writer *w, const char *p) { blob(w,3,p,strlen(p)); }
static void cancel(void *ctx) {
    ctap_credential_engine *e=ctx;
    if (e->crypto_active) (void)key_crypto_job_cancel(e->generation);
    if (e->phase!=IDLE && e->backend) e->backend->abort(e->backend_context);
    const ctap_credential_backend *backend=e->backend; void *backend_context=e->backend_context;
    mbedtls_platform_zeroize(e,sizeof(*e)); e->backend=backend; e->backend_context=backend_context;
}
void ctap_credential_init(ctap_credential_engine *e, const ctap_credential_backend *b, void *ctx) {
    memset(e,0,sizeof(*e)); e->backend=b; e->backend_context=ctx;
}
static size_t fail(ctap_credential_engine *e, uint8_t code, uint8_t *out, size_t cap) {
    cancel(e); if (!cap) return 0; out[0]=code; return 1;
}
static bool available(const ctap_credential_engine *e) {
    const ctap_credential_backend *b=e->backend;
    return b && b->ready && b->pressed && b->random && b->lookup && b->create &&
           b->reserve_counter && b->commit && b->abort && b->ready(e->backend_context);
}
static bool valid_record(ctap_credential_engine *e) {
    ctap_credential_record *c=&e->credential;
    return c->id_length && c->id_length<=256 && c->user_length && c->user_length<=64 &&
           memcmp(c->rp_hash,e->rp_hash,32)==0;
}
static size_t begin(void *ctx, uint32_t cid, const uint8_t *p, size_t n, uint32_t now,
                    uint8_t *out, size_t cap) {
    ctap_credential_engine *e=ctx;
    if (e->phase!=IDLE) return fail(e,0x7f,out,cap);
    if (!n || (p[0]!=1 && p[0]!=2)) return ctap_dispatch(p,n,out,cap);
    uint8_t rc=ctap_request_decode(p,n,&e->request);
    if (rc) return fail(e,rc,out,cap);
    key_cbor_item root, item, options;
    (void)key_cbor_parse(p+1,n-1,&root);
    bool make=e->request.command==1;
    if (e->request.uv) return fail(e,0x2c,out,cap);
    if (make && e->request.has_up) return fail(e,0x2c,out,cap); /* FIDO_2_0 */
    if (make && e->request.rk) return fail(e,0x2b,out,cap); /* Resident backend pending. */
    if (!make && key_cbor_map_uint(&root,5,&options) && key_cbor_map_text(&options,"rk",&item))
        return fail(e,0x2b,out,cap);
    if (key_cbor_map_uint(&root,make?8:6,&item) || key_cbor_map_uint(&root,make?9:7,&item))
        return fail(e,0x2b,out,cap); /* Never accept unverified PIN authentication. */
    if (!available(e)) return fail(e,0x27,out,cap);
    if (!make && (!e->request.has_credentials || !e->request.credentials.value))
        return fail(e,0x2e,out,cap);
    if (next_generation==UINT32_MAX) return fail(e,0x7f,out,cap);
    e->generation=++next_generation; e->cid=cid;
    if (key_crypto_sha256(e->request.rp_id,e->request.rp_id_length,e->rp_hash))
        return fail(e,0x7f,out,cap);
    e->phase=SELECT;
    (void)now; return 0;
}
static size_t wait_presence(ctap_credential_engine *e, uint32_t now, uint8_t *out, size_t cap) {
    if (e->request.command==2 && !e->request.up) { e->phase=COUNTER; return 0; }
    if (!key_presence_begin(&e->presence,e->cid,e->generation,
                            e->backend->pressed(e->backend_context),now)) return fail(e,0x7f,out,cap);
    e->phase=WAIT_UP; return 0;
}
static size_t encode(ctap_credential_engine *e, uint8_t *out, size_t cap) {
    writer w={.out=out,.capacity=cap}; byte(&w,0); byte(&w,0xa3);
    if (e->request.command==1) {
        byte(&w,1); text(&w,"none"); byte(&w,2); blob(&w,2,e->authdata,e->auth_length);
        byte(&w,3); byte(&w,0xa0);
    } else {
        byte(&w,1); byte(&w,0xa2); text(&w,"id"); blob(&w,2,e->credential.id,e->credential.id_length);
        text(&w,"type"); text(&w,"public-key"); byte(&w,2); blob(&w,2,e->authdata,e->auth_length);
        byte(&w,3); blob(&w,2,e->result,e->result_length);
    }
    if (w.failed) return fail(e,0x7f,out,cap);
    size_t n=w.used; cancel(e); return n;
}
static size_t poll(void *ctx, uint32_t now, uint8_t *out, size_t cap, uint8_t *status) {
    ctap_credential_engine *e=ctx;
    *status=1;
    if (e->phase==IDLE || !available(e)) return fail(e,0x27,out,cap);
    int rc;
    if (e->phase==SELECT) {
        if (!e->request.has_credentials || e->descriptor_index>=e->request.credentials.value) {
            if (e->request.command==2) return fail(e,0x2e,out,cap);
            return wait_presence(e,now,out,cap);
        }
        key_cbor_item descriptor, id, type;
        (void)key_cbor_array_at(&e->request.credentials,e->descriptor_index,&descriptor);
        (void)key_cbor_map_text(&descriptor,"id",&id); (void)key_cbor_map_text(&descriptor,"type",&type);
        if (!key_cbor_text_equals(&type,"public-key")) { e->descriptor_index++; return 0; }
        rc=e->backend->lookup(e->backend_context,e->rp_hash,id.data,id.data_length,&e->credential);
        if (rc==CTAP_BACKEND_PENDING) return 0;
        if (rc==0x2e) { mbedtls_platform_zeroize(&e->credential,sizeof(e->credential)); e->descriptor_index++; return 0; }
        if (rc) return fail(e,rc>0 && rc<256?(uint8_t)rc:0x7f,out,cap);
        if (!valid_record(e) || e->credential.id_length!=id.data_length ||
            memcmp(e->credential.id,id.data,id.data_length)) return fail(e,0x7f,out,cap);
        if (e->request.command==1) {
            e->excluded=true; mbedtls_platform_zeroize(&e->credential,sizeof(e->credential));
        }
        return wait_presence(e,now,out,cap);
    }
    if (e->phase==WAIT_UP) {
        *status=2;
        key_presence_status presence=key_presence_sample(&e->presence,e->backend->pressed(e->backend_context),now);
        if (presence==KEY_PRESENCE_TIMED_OUT) return fail(e,e->excluded?0x19:0x2f,out,cap);
        if (presence!=KEY_PRESENCE_APPROVED) return 0;
        if (!key_presence_consume(&e->presence,e->cid,e->generation,now)) return fail(e,0x7f,out,cap);
        if (e->excluded) return fail(e,0x19,out,cap);
        e->authorized=true; e->phase=e->request.command==1?CREATE:COUNTER; return 0;
    }
    if (e->phase==CREATE) {
        rc=e->backend->create(e->backend_context,e->rp_hash,e->request.user_id,
                             e->request.user_id_length,&e->credential);
        if (rc==CTAP_BACKEND_PENDING) return 0;
        if (rc) return fail(e,rc>0 && rc<256?(uint8_t)rc:0x7f,out,cap);
        if (!e->authorized || !valid_record(e) || e->credential.user_length!=e->request.user_id_length ||
            memcmp(e->credential.user_id,e->request.user_id,e->request.user_id_length)) return fail(e,0x7f,out,cap);
        rc=key_crypto_job_begin(e->generation,KEY_CRYPTO_JOB_PUBLIC,e->credential.private_key,NULL,
                               e->backend->random,e->backend_context);
        if (rc) return fail(e,0x7f,out,cap);
        e->crypto_active=true; e->phase=PUBLIC; return 0;
    }
    if (e->phase==PUBLIC || e->phase==SIGN) {
        rc=key_crypto_job_poll(e->generation);
        if (rc==KEY_CRYPTO_PENDING) return 0;
        if (rc || key_crypto_job_take(e->generation,e->result,sizeof(e->result),&e->result_length))
            return fail(e,0x7f,out,cap);
        e->crypto_active=false;
        if (e->phase==SIGN) return encode(e,out,cap);
        if (e->result_length!=65 || key_authdata_from_public(e->request.rp_id,e->request.rp_id_length,
            e->result,e->credential.id,e->credential.id_length,0,e->authdata,sizeof(e->authdata),&e->auth_length))
            return fail(e,0x7f,out,cap);
        e->phase=COMMIT; return 0;
    }
    if (e->phase==COMMIT) {
        rc=e->backend->commit(e->backend_context,&e->credential);
        if (rc==CTAP_BACKEND_PENDING) return 0;
        if (rc) return fail(e,rc>0 && rc<256?(uint8_t)rc:0x7f,out,cap);
        return encode(e,out,cap);
    }
    if (e->phase==COUNTER) {
        rc=e->backend->reserve_counter(e->backend_context,&e->counter);
        if (rc==CTAP_BACKEND_PENDING) return 0;
        if (rc || !e->counter) return fail(e,rc>0 && rc<256?(uint8_t)rc:0x7f,out,cap);
        if ((e->request.up && !e->authorized) || key_authdata_assert(e->request.rp_id,e->request.rp_id_length,
            e->counter,e->authorized,e->authdata,sizeof(e->authdata))) return fail(e,0x7f,out,cap);
        e->auth_length=37;
        if (key_authdata_digest(e->authdata,e->auth_length,e->request.client_data_hash,e->digest))
            return fail(e,0x7f,out,cap);
        if (key_crypto_job_begin(e->generation,KEY_CRYPTO_JOB_SIGN,e->credential.private_key,e->digest,
            e->backend->random,e->backend_context)) return fail(e,0x7f,out,cap);
        /* Signing job owns the scalar now; do not keep an unnecessary second
         * plaintext key copy in the credential selection buffer. */
        mbedtls_platform_zeroize(e->credential.private_key,sizeof(e->credential.private_key));
        e->crypto_active=true; e->phase=SIGN; return 0;
    }
    return fail(e,0x7f,out,cap);
}
static uint8_t timeout_status(void *ctx) {
    const ctap_credential_engine *e=ctx; return e->excluded?0x19:0x2f;
}
const ctaphid_jobs ctap_credential_jobs={begin,poll,cancel,timeout_status};
