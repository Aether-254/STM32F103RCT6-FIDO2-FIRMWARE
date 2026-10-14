#ifndef KEY_ROOT_H
#define KEY_ROOT_H
#include "key_crypto.h"
#define KEY_ROOT_BLOCK_SIZE 128u
/* Plaintext root configuration codec ONLY. Does not generate entropy or write
 * flash. Hash is an accidental corruption/torn-write checksum, NOT protection
 * from a physical attacker who can read/rewrite root and checksum together.
 * Source root must be fresh trusted CSPRNG material, never UID/time/test keys.
 * Inputs/outputs must not overlap. Provisioning requires separate authorization
 * and must program/readback body before final commit halfword. */
KEY_CRYPTO_API int key_root_encode(const uint8_t root[32], const uint8_t device[12],
                                  uint8_t block[KEY_ROOT_BLOCK_SIZE]);
/* Require exact size, committed marker, expected public device binding and
 * canonical checksum/padding. Output is wiped on every failure. Existing root
 * with missing/invalid journal must never trigger automatic genesis. */
KEY_CRYPTO_API int key_root_decode(const uint8_t *block, size_t length,
                                  const uint8_t expected_device[12], uint8_t root[32]);
#endif
