#ifndef BOARD_KEYS_H
#define BOARD_KEYS_H
#include <stdint.h>
#include <stdbool.h>
/* Vendor MINI pinout: KEY1 PA0 / KEY2 PC13, active-high. Actual board verification
 * pending. Capacitive PA1/touch are NOT accepted as consent inputs yet. */
typedef struct {
    uint32_t magic, sequence, tick, raw_mask, key1_raw_rises, key2_raw_rises;
} board_keys_diagnostics;
extern volatile board_keys_diagnostics board_keys_snapshot;
void board_keys_init(void);
void board_keys_poll(void);
bool board_keys_pressed(void *);
#endif
