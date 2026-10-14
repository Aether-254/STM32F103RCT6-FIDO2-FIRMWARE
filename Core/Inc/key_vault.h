#ifndef KEY_VAULT_H
#define KEY_VAULT_H
#include "ctap_credential.h"
#define KEY_VAULT_BLOCK_SIZE 512u
#define KEY_VAULT_BAD_INPUT (-1)
#define KEY_VAULT_AUTH_FAILED (-2)
#define KEY_VAULT_CRYPTO_FAILED (-3)
/* Foreground-only codec, NOT a storage backend or nonce allocator.
 * root is an externally provisioned secret; context is a public 12B device
 * binding, not entropy. Caller MUST durably reserve a unique nonzero sequence
 * under this root/context BEFORE seal, including cancelled/failed writes.
 * Never reset the sequence when deleting credentials or restoring an SD card.
 * AEAD does not detect replay of an older valid block. An independently trusted
 * journal is required. Input/output buffers must not overlap. */
KEY_CRYPTO_API int key_vault_seal(const uint8_t root[32], const uint8_t context[12],
    uint64_t sequence, const ctap_credential_record *record,
    uint8_t block[KEY_VAULT_BLOCK_SIZE]);
/* expected RP and ID must come from the requested credential, not untrusted
 * block metadata alone. Output is zeroed on every failure. No partial plaintext
 * is exposed. All-zero root/private scalar is rejected; other invalid P-256
 * scalars must be rejected by key generation/ECC before committing a record. */
KEY_CRYPTO_API int key_vault_open(const uint8_t root[32], const uint8_t context[12],
    const uint8_t expected_rp[32], const uint8_t *expected_id, size_t id_length,
    const uint8_t *block, size_t block_length, ctap_credential_record *record);
#endif
