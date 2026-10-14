#ifndef CTAP_CREDENTIAL_H
#define CTAP_CREDENTIAL_H
#include "ctaphid.h"
#include "ctap_request.h"
#include "key_presence.h"
#include "key_crypto.h"
#include "key_authdata.h"
#define CTAP_BACKEND_PENDING 256
typedef struct {
    uint8_t private_key[32], rp_hash[32], id[256], user_id[64];
    size_t id_length, user_length;
} ctap_credential_record;
/* Trusted foreground backend. Each operation must be bounded, returning
 * PENDING while unfinished, 0 success or a CTAP error. Repeated PENDING calls
 * have identical input and must not allocate multiple keys/counters/commits.
 * ready requires trusted key generation, physical input, and durable storage.
 * reserve_counter commits a strictly increasing NONZERO count before success.
 * commit durably saves a candidate before any MakeCredential success response.
 * abort releases pending state, never rolls back a committed counter/record. */
typedef struct {
    bool (*ready)(void *);
    bool (*pressed)(void *);
    key_crypto_random_fn random;
    int (*lookup)(void *, const uint8_t[32], const uint8_t *, size_t, ctap_credential_record *);
    int (*create)(void *, const uint8_t[32], const uint8_t *, size_t, ctap_credential_record *);
    int (*reserve_counter)(void *, uint32_t *);
    int (*commit)(void *, const ctap_credential_record *);
    void (*abort)(void *);
} ctap_credential_backend;
typedef struct {
    const ctap_credential_backend *backend;
    void *backend_context;
    ctap_request request;
    key_presence presence;
    ctap_credential_record credential;
    uint8_t rp_hash[32], authdata[KEY_AUTHDATA_MAX_SIZE], digest[32], result[72];
    size_t auth_length, result_length, descriptor_index;
    uint32_t cid, generation, counter;
    unsigned phase;
    bool excluded, crypto_active, authorized;
} ctap_credential_engine;
/* Call cancel before reinitializing a live engine. NULL backend fails closed. */
void ctap_credential_init(ctap_credential_engine *, const ctap_credential_backend *, void *);
/* Foreground UI query only; never polls input, authorizes, or mutates a job. */
uint32_t ctap_credential_presence_progress(const ctap_credential_engine *, uint32_t now);
extern const ctaphid_jobs ctap_credential_jobs;
#endif
