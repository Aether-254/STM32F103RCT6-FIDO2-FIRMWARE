#include "key_backend.h"
#include "mbedtls/platform_util.h"
#include <string.h>
enum { NONE, LOOKUP, CREATE_CHECK, CANDIDATE, WRITE, VERIFY };
static void transient(key_backend *b) {
    mbedtls_platform_zeroize(b->block, sizeof(b->block));
    mbedtls_platform_zeroize(b->rp, sizeof(b->rp));
    mbedtls_platform_zeroize(b->id, sizeof(b->id));
    mbedtls_platform_zeroize(b->candidate_hash, sizeof(b->candidate_hash));
    mbedtls_platform_zeroize(b->block_hash, sizeof(b->block_hash));
    b->phase = NONE; b->collisions = 0;
}
static void abort_operation(void *ctx) {
    key_backend *b = ctx;
    if (!b) return;
    if (b->store && b->store->abort) b->store->abort(b->store_context);
    transient(b);
}
static int failed(key_backend *b, int rc) {
    abort_operation(b);
    return rc > 0 && rc < 256 ? rc : 0x7f;
}
static bool ready(void *ctx) {
    key_backend *b = ctx;
    return b && b->initialized && b->journal && b->journal->ready &&
        key_random_bound(b->journal) && b->store->ready(b->store_context);
}
static bool pressed(void *ctx) {
    key_backend *b = ctx;
    return ready(ctx) && b->input_pressed(b->input_context);
}
static int random_bytes(void *ctx, unsigned char *out, size_t n) {
    if (!ready(ctx)) {
        if (out && n <= KEY_RANDOM_MAX_REQUEST) mbedtls_platform_zeroize(out, n);
        return KEY_CRYPTO_NO_RANDOM;
    }
    return key_random_bytes(NULL, out, n);
}
static int fingerprint(const ctap_credential_record *r, uint8_t hash[32]) {
    /* In-memory transaction identity only, NOT a persisted native struct.
     * create memset() initializes every byte including padding. Frontend owns
     * this same record, immutable until commit/cancel. */
    return key_crypto_sha256((const uint8_t *)r, sizeof(*r), hash);
}
static bool candidate_matches(key_backend *b, const ctap_credential_record *r) {
    uint8_t hash[32];
    if (fingerprint(r, hash)) return false;
    uint8_t difference = 0;
    for (unsigned i = 0; i < 32; ++i) difference |= hash[i] ^ b->candidate_hash[i];
    mbedtls_platform_zeroize(hash, sizeof(hash));
    return difference == 0;
}
static int lookup(void *ctx, const uint8_t rp[32], const uint8_t *id, size_t n, ctap_credential_record *out) {
    key_backend *b = ctx;
    if (!out) return 0x7f;
    memset(out, 0, sizeof(*out));
    if (!ready(ctx) || !rp || !id) return b ? failed(b, 0x27) : 0x27;
    if (n != 32 && b->phase == NONE) return 0x2e;
    if (b->phase == NONE) { memcpy(b->rp, rp, 32); memcpy(b->id, id, 32); b->phase = LOOKUP; }
    if (b->phase != LOOKUP || n != 32 || memcmp(b->rp, rp, 32) || memcmp(b->id, id, 32)) return failed(b, 0x7f);
    int rc = b->store->read(b->store_context, b->rp, b->id, b->block);
    if (rc == CTAP_BACKEND_PENDING) return rc;
    if (rc) return failed(b, rc);
    rc = key_vault_open(b->root, b->device, b->rp, b->id, 32, b->block, 512, out);
    transient(b);
    return rc ? 0x7f : 0;
}
static int new_candidate(key_backend *b, const uint8_t rp[32], const uint8_t *user, size_t n,
                         ctap_credential_record *out) {
    memset(out, 0, sizeof(*out));
    memcpy(out->rp_hash, rp, 32); memcpy(out->user_id, user, n);
    out->id_length = 32; out->user_length = n;
    if (key_random_private(out->private_key) || random_bytes(b, out->id, 32) ||
        fingerprint(out, b->candidate_hash)) {
        mbedtls_platform_zeroize(out, sizeof(*out)); return failed(b, 0x7f);
    }
    memcpy(b->rp, rp, 32); memcpy(b->id, out->id, 32); b->phase = CREATE_CHECK;
    return 0;
}
static int create(void *ctx, const uint8_t rp[32], const uint8_t *user, size_t n, ctap_credential_record *out) {
    key_backend *b = ctx;
    if (!out) return 0x7f;
    if (!ready(ctx) || !rp || !user || !n || n > 64) {
        mbedtls_platform_zeroize(out, sizeof(*out)); return b ? failed(b, 0x27) : 0x27;
    }
    if (b->phase == NONE && new_candidate(b, rp, user, n, out)) return 0x7f;
    if ((b->phase != CREATE_CHECK && b->phase != CANDIDATE) || !candidate_matches(b, out) ||
        memcmp(out->rp_hash, rp, 32) || out->user_length != n || memcmp(out->user_id, user, n)) {
        mbedtls_platform_zeroize(out, sizeof(*out)); return failed(b, 0x7f);
    }
    if (b->phase == CANDIDATE) return 0;
    int rc = b->store->read(b->store_context, b->rp, b->id, b->block);
    if (rc == CTAP_BACKEND_PENDING) return rc;
    if (rc == 0x2e) { mbedtls_platform_zeroize(b->block, sizeof(b->block)); b->phase = CANDIDATE; return 0; }
    if (rc) { mbedtls_platform_zeroize(out, sizeof(*out)); return failed(b, rc); }
    /* Found an existing ID: regenerate, never overwrite. Cooperative retry. */
    if (++b->collisions >= 16) { mbedtls_platform_zeroize(out, sizeof(*out)); return failed(b, 0x28); }
    if (new_candidate(b, rp, user, n, out)) return 0x7f;
    return CTAP_BACKEND_PENDING;
}
static int nonce(key_backend *b, uint64_t *value) {
    if (!b->nonce_left) {
        uint64_t available = UINT64_MAX-b->journal->state.nonce;
        uint64_t amount = available < KEY_BACKEND_NONCE_BATCH ? available : KEY_BACKEND_NONCE_BATCH;
        uint32_t unused;
        if (!amount) return 0x28;
        int rc = key_journal_reserve(b->journal, amount, 0, &b->nonce_next, &unused);
        if (rc) return rc == KEY_JOURNAL_EXHAUSTED ? 0x28 : 0x7f;
        b->nonce_left = (uint32_t)amount;
    }
    *value = b->nonce_next;
    --b->nonce_left;
    b->nonce_next = b->nonce_left ? b->nonce_next+1 : 0;
    return 0;
}
static int reserve_counter(void *ctx, uint32_t *out) {
    key_backend *b = ctx;
    if (!out) return 0x7f;
    *out = 0;
    if (!ready(ctx)) return 0x27;
    if (b->phase != NONE) return failed(b, 0x7f);
    if (!b->sign_left) {
        uint32_t available = UINT32_MAX-b->journal->state.sign_count;
        uint32_t amount = available < KEY_BACKEND_SIGN_BATCH ? available : KEY_BACKEND_SIGN_BATCH;
        uint64_t unused;
        if (!amount) return 0x28;
        int rc = key_journal_reserve(b->journal, 0, amount, &unused, &b->sign_next);
        if (rc) return rc == KEY_JOURNAL_EXHAUSTED ? 0x28 : 0x7f;
        b->sign_left = amount;
    }
    *out = b->sign_next;
    --b->sign_left;
    b->sign_next = b->sign_left ? b->sign_next+1 : 0;
    return 0;
}
static int commit(void *ctx, const ctap_credential_record *r) {
    key_backend *b = ctx;
    if (!ready(ctx) || !r) return b ? failed(b, 0x27) : 0x27;
    if ((b->phase != CANDIDATE && b->phase != WRITE && b->phase != VERIFY) || !candidate_matches(b, r))
        return failed(b, 0x7f);
    if (b->phase == CANDIDATE) {
        uint64_t sequence;
        int rc = nonce(b, &sequence);
        if (rc) return failed(b, rc);
        if (key_vault_seal(b->root, b->device, sequence, r, b->block) ||
            key_crypto_sha256(b->block, 512, b->block_hash)) return failed(b, 0x7f);
        b->phase = WRITE;
        return CTAP_BACKEND_PENDING;
    }
    if (b->phase == WRITE) {
        int rc = b->store->write_new(b->store_context, b->rp, b->id, b->block);
        if (rc == CTAP_BACKEND_PENDING) return rc;
        if (rc) return failed(b, rc);
        b->phase = VERIFY; return CTAP_BACKEND_PENDING;
    }
    int rc = b->store->read(b->store_context, b->rp, b->id, b->block);
    if (rc == CTAP_BACKEND_PENDING) return rc;
    if (rc) return failed(b, rc == 0x2e ? 0x7f : rc);
    uint8_t hash[32];
    rc = key_crypto_sha256(b->block, 512, hash);
    uint8_t difference = 0;
    for (unsigned i = 0; i < 32; ++i) difference |= hash[i] ^ b->block_hash[i];
    mbedtls_platform_zeroize(hash, sizeof(hash));
    if (rc || difference) return failed(b, 0x7f);
    transient(b); return 0;
}
const ctap_credential_backend key_backend_ops = {ready, pressed, random_bytes, lookup, create, reserve_counter, commit, abort_operation};
int key_backend_init(key_backend *b, key_journal *journal, const uint8_t root[32], const uint8_t device[12],
    const key_store_io *store, void *store_context, bool (*input)(void *), void *input_context) {
    if (!b) return KEY_CRYPTO_BAD_INPUT;
    memset(b, 0, sizeof(*b));
    if (!store || !store->ready || !store->read || !store->write_new || !store->abort || !input ||
        !key_journal_matches(journal, root, device) || !key_random_bound(journal)) return KEY_CRYPTO_BAD_INPUT;
    b->store = store; b->store_context = store_context; b->input_pressed = input; b->input_context = input_context;
    b->journal = journal; memcpy(b->root, root, 32); memcpy(b->device, device, 12); b->initialized = true;
    return 0;
}
void key_backend_dispose(key_backend *b) {
    if (!b) return;
    if (b->initialized) abort_operation(b);
    mbedtls_platform_zeroize(b, sizeof(*b));
}
