#include "ctaphid.h"
#include "ctap_dispatch.h"
#include "ctap_request.h"
#include "key_crypto.h"
#include "ctap_credential.h"
#include "key_backend.h"
#include <string.h>
#ifdef _WIN32
#define API __declspec(dllexport)
#else
#define API
#endif
static ctaphid_state state;
API void reset(void) { ctaphid_dispose(&state); ctaphid_init(&state,ctap_dispatch); }
API void receive(const uint8_t *p, size_t n, uint32_t now) { ctaphid_receive(&state,p,n,now); }
API void tick(uint32_t now) { ctaphid_tick(&state,now); }
API int peek(uint8_t *p, uint32_t *ticket) { return ctaphid_peek(&state,p,ticket); }
API void ack(uint32_t ticket) { ctaphid_ack(&state,ticket); }
API unsigned dropped_errors(void) { return state.dropped_errors; }
API int idle(void) { return !state.receiving && !state.transmitting && !state.executing; }
API size_t dispatch(const uint8_t *p, size_t n, uint8_t *out, size_t cap) {
    return ctap_dispatch(p,n,out,cap);
}
API int cbor_valid(const uint8_t *p, size_t n) {
    key_cbor_item item;
    return key_cbor_parse(p,n,&item);
}
API unsigned request_status(const uint8_t *p, size_t n) {
    ctap_request request;
    return ctap_request_decode(p,n,&request);
}
static unsigned cancellations, polls, mode;
static uint8_t status=2;
static const uint8_t *borrowed;
static size_t borrowed_length;
static key_crypto_random_fn crypto_random;
static void *crypto_context;
static uint32_t crypto_generation=1;
static bool crypto_active;
static size_t job_begin(void *ctx, uint32_t cid, const uint8_t *p, size_t n,
                        uint32_t now, uint8_t *out, size_t cap) {
    (void)ctx; (void)cid; (void)now; (void)cap;
    borrowed=p; borrowed_length=n;
    if (mode==4) {
        ctap_request request;
        uint8_t rc=ctap_request_decode(p,n,&request);
        if (rc) { out[0]=rc; borrowed=NULL; return 1; }
        /* Public HOST-ONLY test scalar; this harness is never in firmware. */
        uint8_t private_key[32]={0}; private_key[31]=17;
        crypto_generation++; if (!crypto_generation) crypto_generation++;
        if (key_crypto_job_begin(crypto_generation,KEY_CRYPTO_JOB_SIGN,private_key,
            request.client_data_hash,crypto_random,crypto_context)) {
            out[0]=0x7f; borrowed=NULL; return 1;
        }
        crypto_active=true;
    }
    if (mode==2) { out[0]=0; borrowed=NULL; return 1; }
    return 0;
}
static size_t job_poll(void *ctx, uint32_t now, uint8_t *out, size_t cap, uint8_t *s) {
    (void)ctx; (void)now; (void)cap; polls++; *s=status;
    if (mode==4) {
        int rc=key_crypto_job_poll(crypto_generation);
        if (rc==KEY_CRYPTO_PENDING) return 0;
        size_t length=0;
        if (!rc) rc=key_crypto_job_take(crypto_generation,out+1,cap-1,&length);
        if (rc) (void)key_crypto_job_cancel(crypto_generation);
        crypto_active=false; borrowed=NULL; out[0]=rc?0x7f:0;
        return rc?1:length+1;
    }
    if (mode==1) {
        memcpy(out,borrowed,borrowed_length); size_t n=borrowed_length;
        borrowed=NULL; return n;
    }
    if (mode==3) { borrowed=NULL; return CTAPHID_MAX_MESSAGE+1; }
    return 0;
}
static void job_cancel(void *ctx) {
    (void)ctx; cancellations++; borrowed=NULL;
    if (crypto_active) (void)key_crypto_job_cancel(crypto_generation);
    crypto_active=false;
}
static const ctaphid_jobs jobs={job_begin,job_poll,job_cancel,NULL};
API int jobs_enable(void) {
    cancellations=polls=mode=0; status=1; borrowed=NULL;
    return ctaphid_set_jobs(&state,&jobs,NULL);
}
API int jobs_crypto_enable(key_crypto_random_fn random, void *context) {
    if (!jobs_enable()) return 0;
    crypto_random=random; crypto_context=context; mode=4; return 1;
}
API void jobs_mode(unsigned value) { mode=value; }
API void jobs_status(unsigned value) { status=(uint8_t)value; }
API unsigned jobs_cancelled(void) { return cancellations; }
API unsigned jobs_polled(void) { return polls; }
API int jobs_borrowed(void) { return borrowed!=NULL; }
API void dispose(void) { ctaphid_dispose(&state); }

/* HOST-ONLY ephemeral backend. Never linked into device firmware. */
static ctap_credential_engine frontend;
static ctap_credential_record records[8];
static unsigned record_count, frontend_counter, operation, fail_operation, delay, remaining, aborts;
static bool frontend_ready, frontend_pressed;
static key_crypto_random_fn frontend_random;
static bool ready(void *ctx) { (void)ctx; return frontend_ready; }
static bool pressed(void *ctx) { (void)ctx; return frontend_pressed; }
static int random_bytes(void *ctx, unsigned char *p, size_t n) { (void)ctx; return frontend_random(NULL,p,n); }
static int pending(unsigned op) {
    if (operation!=op) { operation=op; remaining=delay; }
    if (remaining) { remaining--; return CTAP_BACKEND_PENDING; }
    return fail_operation==op?0x7f:0;
}
static int lookup(void *ctx, const uint8_t rp[32], const uint8_t *id, size_t n, ctap_credential_record *out) {
    (void)ctx; int rc=pending(1); if (rc) return rc;
    for (unsigned i=0; i<record_count; i++) {
        if (records[i].id_length==n && !memcmp(records[i].id,id,n) && !memcmp(records[i].rp_hash,rp,32)) {
            *out=records[i]; if (fail_operation==5) out->rp_hash[0]^=1; return 0;
        }
    }
    return 0x2e;
}
static int create(void *ctx, const uint8_t rp[32], const uint8_t *user, size_t n, ctap_credential_record *out) {
    (void)ctx; int rc=pending(2); if (rc) return rc;
    memset(out,0,sizeof(*out)); memcpy(out->rp_hash,rp,32); memcpy(out->user_id,user,n);
    out->user_length=n; out->id_length=32;
    if (random_bytes(NULL,out->private_key,32) || random_bytes(NULL,out->id,32)) return 0x7f;
    if (fail_operation==6) out->user_id[0]^=1;
    return 0;
}
static int reserve_counter(void *ctx, uint32_t *out) {
    (void)ctx; int rc=pending(3); if (rc) return rc;
    if (frontend_counter==UINT32_MAX) return 0x28;
    *out=++frontend_counter; if (fail_operation==7) *out=0; return 0;
}
static int commit(void *ctx, const ctap_credential_record *record) {
    (void)ctx; int rc=pending(4); if (rc) return rc;
    if (record_count>=8) return 0x28;
    records[record_count++]=*record; return 0;
}
static void backend_abort(void *ctx) { (void)ctx; operation=0; remaining=0; aborts++; }
static const ctap_credential_backend backend={ready,pressed,random_bytes,lookup,create,reserve_counter,commit,backend_abort};
API int frontend_enable(key_crypto_random_fn random) {
    memset(records,0,sizeof(records)); record_count=frontend_counter=operation=fail_operation=delay=remaining=aborts=0;
    frontend_ready=true; frontend_pressed=false; frontend_random=random;
    ctap_credential_init(&frontend,&backend,NULL);
    return ctaphid_set_jobs(&state,&ctap_credential_jobs,&frontend);
}
API int frontend_no_backend(void) {
    ctap_credential_init(&frontend,NULL,NULL);
    return ctaphid_set_jobs(&state,&ctap_credential_jobs,&frontend);
}
API void frontend_press(int value) { frontend_pressed=value!=0; }
API void frontend_set_ready(int value) { frontend_ready=value!=0; }
API void frontend_fail(unsigned value) { fail_operation=value; }
API void frontend_delay(unsigned value) { delay=value; }
API unsigned frontend_stored(void) { return record_count; }
API unsigned frontend_count(void) { return frontend_counter; }
API unsigned frontend_phase(void) { return frontend.phase; }
API uint32_t frontend_progress(uint32_t now) { return ctap_credential_presence_progress(&frontend,now); }
API void frontend_count_set(unsigned value) { frontend_counter=value; }
API int frontend_clean(void) {
    ctap_credential_engine copy=frontend; copy.backend=NULL; copy.backend_context=NULL;
    const uint8_t *p=(const uint8_t *)&copy;
    for (size_t i=0; i<sizeof(copy); i++) if (p[i]) return 0;
    return 1;
}

/* Actual portable persistent backend, but host-only adapter/input binding. */
static key_backend persistent;
API int persistent_enable(key_journal *journal, const uint8_t root[32], const uint8_t device[12],
    const key_store_io *store, void *store_context, bool (*input)(void *), void *input_context) {
    if (key_backend_init(&persistent,journal,root,device,store,store_context,input,input_context)) return 0;
    ctap_credential_init(&frontend,&key_backend_ops,&persistent);
    return ctaphid_set_jobs(&state,&ctap_credential_jobs,&frontend);
}
API void persistent_close(void) {
    ctaphid_dispose(&state); key_backend_dispose(&persistent); key_random_stop();
}
API unsigned persistent_phase(void) { return persistent.phase; }
API unsigned persistent_sign_left(void) { return persistent.sign_left; }
API unsigned persistent_nonce_left(void) { return persistent.nonce_left; }
API int persistent_transient_clean(void) {
    if (persistent.phase || persistent.collisions) return 0;
    const uint8_t *regions[]={persistent.block,persistent.rp,persistent.id,persistent.candidate_hash,persistent.block_hash};
    const size_t sizes[]={512,32,32,32,32};
    for (unsigned r=0;r<5;r++) for (size_t i=0;i<sizes[r];i++) if (regions[r][i]) return 0;
    return 1;
}
