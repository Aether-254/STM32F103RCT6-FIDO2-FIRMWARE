#ifndef KEY_AUTHDATA_H
#define KEY_AUTHDATA_H
#include "key_crypto.h"
#include <stdbool.h>
#define KEY_AUTHDATA_MAX_SIZE 388u
/* Protocol serialization ONLY. The credential job must first verify fresh UP,
 * authorize RP/credential use and durably allocate signCount. This module is
 * not an authorization or persistence boundary. Output carries no UV claim. */
KEY_CRYPTO_API int key_authdata_make(const uint8_t *rp_id, size_t rp_length,
    const uint8_t private_key[32], const uint8_t *credential_id, size_t credential_length,
    uint32_t sign_count, uint8_t *output, size_t capacity, size_t *length,
    key_crypto_random_fn random, void *random_context);
KEY_CRYPTO_API int key_authdata_assert(const uint8_t *rp_id, size_t rp_length,
    uint32_t sign_count, bool user_present, uint8_t *output, size_t capacity);
/* Internal serializer: public key must be a validated result from crypto job
 * take, not arbitrary caller input. Avoids a second blocking multiplication. */
int key_authdata_from_public(const uint8_t *rp_id, size_t rp_length,
    const uint8_t public_key[65], const uint8_t *credential_id, size_t credential_length,
    uint32_t sign_count, uint8_t *output, size_t capacity, size_t *length);
/* Hashes authenticatorData || clientDataHash (not the raw JSON) for ES256. */
KEY_CRYPTO_API int key_authdata_digest(const uint8_t *authdata, size_t length,
    const uint8_t client_data_hash[32], uint8_t digest[32]);
#endif
