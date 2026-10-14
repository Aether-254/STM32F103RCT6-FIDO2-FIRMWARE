#ifndef BOARD_SD_H
#define BOARD_SD_H
#include <stdint.h>
/* Read-only startup diagnostics, never a credential storage provider. */
typedef struct {
    uint32_t magic, sequence, tick;
    int32_t init_result, read_result;
    uint64_t sectors;
    uint8_t csd[16], cid[16];
    uint32_t sector0_signature;
} board_sd_diagnostics;
extern volatile board_sd_diagnostics board_sd_snapshot;
void board_sd_diagnose(void);
#endif
