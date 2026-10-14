#ifndef KEY_JOURNAL_H
#define KEY_JOURNAL_H
#include "key_crypto.h"
#include <stdbool.h>
#define KEY_JOURNAL_PAGE_SIZE 2048u
#define KEY_JOURNAL_ENTRY_SIZE 80u
#define KEY_JOURNAL_SLOTS 25u
#define KEY_JOURNAL_BAD_INPUT (-1)
#define KEY_JOURNAL_UNPROVISIONED (-2)
#define KEY_JOURNAL_CORRUPT (-3)
#define KEY_JOURNAL_IO_FAILED (-4)
#define KEY_JOURNAL_EXHAUSTED (-5)
/* Relative offsets within two independent 2KiB pages. read/program return 0
 * only after completion; program must enforce 1->0, even offset/length and
 * halfword ordering. erase(page) returns 0 only after durable completion.
 * Actual target driver must obey flash voltage/timing/USB scheduling constraints.
 * These callbacks are synchronous; this portable layer alone is NOT a bounded
 * asynchronous CTAP backend. No HAL flash implementation is bound in main. */
typedef struct {
    int (*read)(void *, size_t, uint8_t *, size_t);
    int (*program)(void *, size_t, const uint8_t *, size_t);
    int (*erase)(void *, unsigned);
} key_journal_io;
typedef struct {
    uint64_t serial, nonce;
    uint32_t sign_count;
} key_journal_state;
typedef struct {
    const key_journal_io *io;
    void *context;
    uint8_t key[32];
    key_journal_state state;
    key_journal_state page_state[2];
    unsigned next_slot[2];
    bool healthy[2];
    bool ready;
} key_journal;
/* No automatic genesis/reset. recover is read-only. Empty media returns
 * UNPROVISIONED. A fully authenticated prepared record is conservatively burned
 * even if its final marker was not written. No secret is stored in these pages.
 * Successful allocations are mirrored to BOTH pages. Recovery tolerates one
 * bad/partially erased page; repairs redundancy before further allocation.
 * HMAC prevents forgery, NOT replay of an entire on-chip journal snapshot or
 * arbitrary multi-page corruption. v2 format rejects v1; no silent migration. */
KEY_CRYPTO_API int key_journal_recover(key_journal *, const key_journal_io *, void *,
    const uint8_t root[32], const uint8_t device_context[12]);
/* EXPLICIT provisioning writes genesis ONLY if both pages are entirely erased.
 * Requires a fresh/known-never-used root. Blank journal under an existing used
 * root is data loss, NOT permission to reset counters or repeat old nonces.
 * Never call without authorization on real hardware. Never erases automatically. */
KEY_CRYPTO_API int key_journal_provision(key_journal *, const key_journal_io *, void *,
    const uint8_t root[32], const uint8_t device_context[12]);
/* Durable high-water reservation. Outputs are previous+1..previous+amount.
 * Caller may cache/use a range while powered, but MUST discard unconsumed ranges
 * at reboot or backend teardown. Cancellation burns allocations. Output is zero
 * on failure; uncertain I/O poisons this instance until explicit recovery.
 * nonce_amount and sign_amount may independently be zero, not both zero. */
KEY_CRYPTO_API int key_journal_reserve(key_journal *, uint64_t nonce_amount,
    uint32_t sign_amount, uint64_t *nonce_first, uint32_t *sign_first);
KEY_CRYPTO_API void key_journal_dispose(key_journal *);
/* Verify the ready journal is bound to this root/device before DRBG boot. */
KEY_CRYPTO_API bool key_journal_matches(const key_journal *, const uint8_t root[32],
                                      const uint8_t device_context[12]);
#endif
