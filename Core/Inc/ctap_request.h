#ifndef CTAP_REQUEST_H
#define CTAP_REQUEST_H
#include "key_cbor.h"
#define CTAP_MAX_CREDENTIAL_LIST 16u
#define CTAP_MAX_CREDENTIAL_ID 256u
#define CTAP_MAX_RP_ID 253u
typedef struct {
    const uint8_t *rp_id, *client_data_hash, *user_id;
    size_t rp_id_length, user_id_length;
    key_cbor_item credentials;
    bool rk, uv, up, has_up, has_credentials;
    uint8_t command;
} ctap_request;
/* Returns a CTAP status; zero is only schema success, NOT user authorization.
 * Validated fields borrow request bytes and must be copied before async work. */
uint8_t ctap_request_decode(const uint8_t *request, size_t length, ctap_request *out);
#endif
