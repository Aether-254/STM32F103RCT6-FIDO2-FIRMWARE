#ifndef KEY_BACKEND_H
#define KEY_BACKEND_H
#include "ctap_credential.h"
#include "key_journal.h"
#include "key_vault.h"
#include "key_random.h"
#define KEY_BACKEND_NONCE_BATCH 64u
#define KEY_BACKEND_SIGN_BATCH 32u
/* Trusted storage adapter for immutable 32B-ID nonresident credential objects.
 * Paths/index must bind BOTH RP hash and ID. read: 0=exact authenticated object
 * bytes available, 0x2e=absent, 256=pending, other=CTAP error. write_new must
 * NEVER overwrite existing objects and return 0 only after durable completion.
 * Repeated PENDING calls are the SAME operation and buffers stay owned/stable.
 * abort stops pending I/O, never deletes/reverts an already durable object.
 * Actual FatFs/card flush, atomic publication and target durability unimplemented.
 */
typedef struct {
    bool (*ready)(void *);
    int (*read)(void *, const uint8_t rp[32], const uint8_t id[32], uint8_t block[512]);
    int (*write_new)(void *, const uint8_t rp[32], const uint8_t id[32], const uint8_t block[512]);
    void (*abort)(void *);
} key_store_io;
typedef struct {
    const key_store_io *store;
    void *store_context;
    bool (*input_pressed)(void *);
    void *input_context;
    key_journal *journal;
    uint8_t root[32], device[12];
    uint64_t nonce_next;
    uint32_t nonce_left, sign_next, sign_left;
    /* Transient request state; no private scalar retained after candidate copy. */
    uint8_t block[512], rp[32], id[32], candidate_hash[32], block_hash[32];
    unsigned phase, collisions;
    bool initialized;
} key_backend;
/* Requires already recovered journal and already booted matching RNG. Copies
 * secret root; caller can clear its own copy after success. Does not provision,
 * boot RNG or perform I/O. All provider/adapter/context pointers must outlive it.
 * Do not reinitialize a live backend; cancel and dispose it first.
 * Physical pressed callback must be actual trusted hardware in production.
 * Journal reservations are currently synchronous: bounded board flash scheduling
 * still required before claiming this is a real nonblocking CTAP backend. */
KEY_CRYPTO_API int key_backend_init(key_backend *, key_journal *, const uint8_t root[32],
    const uint8_t device[12], const key_store_io *, void *, bool (*)(void *), void *);
/* Cancel frontend FIRST. Dispose burns cached ranges, wipes root/request state;
 * caller separately owns journal and RNG lifetimes. No committed data deleted. */
KEY_CRYPTO_API void key_backend_dispose(key_backend *);
extern const ctap_credential_backend key_backend_ops;
#endif
