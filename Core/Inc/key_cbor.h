#ifndef KEY_CBOR_H
#define KEY_CBOR_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define KEY_CBOR_MAX_SIZE 4096u
#define KEY_CBOR_MAX_DEPTH 4u
typedef struct {
    const uint8_t *encoded, *data;
    size_t encoded_length, data_length;
    uint64_t value;
    uint8_t major;
} key_cbor_item;
/* Zero-copy views borrow immutable validated input. No heap or unbounded
 * recursion. A view must NOT survive clearing/reusing its source buffer. */
bool key_cbor_parse(const uint8_t *input, size_t length, key_cbor_item *root);
bool key_cbor_map_uint(const key_cbor_item *map, uint64_t key, key_cbor_item *value);
bool key_cbor_map_text(const key_cbor_item *map, const char *key, key_cbor_item *value);
bool key_cbor_array_at(const key_cbor_item *array, size_t index, key_cbor_item *value);
bool key_cbor_text_equals(const key_cbor_item *item, const char *text);
#endif
