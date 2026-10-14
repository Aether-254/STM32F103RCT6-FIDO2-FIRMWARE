#ifndef CTAP_DISPATCH_H
#define CTAP_DISPATCH_H
#include <stddef.h>
#include <stdint.h>
size_t ctap_dispatch(const uint8_t *request, size_t length, uint8_t *response, size_t capacity);
#endif
