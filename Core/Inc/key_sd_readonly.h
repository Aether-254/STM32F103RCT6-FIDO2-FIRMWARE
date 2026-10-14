#ifndef KEY_SD_READONLY_H
#define KEY_SD_READONLY_H
#include <stdbool.h>
#include <stdint.h>
#if defined(KEY_CRYPTO_HOST_TEST) && defined(_WIN32)
#define KEY_SD_API __declspec(dllexport)
#else
#define KEY_SD_API
#endif
/* Foreground SPI adapter. transfer must return promptly with a hardware timeout;
 * poll services USB but must not reenter this driver. tick is monotonic ms.
 * select(false) deasserts CS. No write/erase/format operation exists here. */
typedef struct {
    int (*transfer)(void *, uint8_t, uint8_t *);
    void (*select)(void *, bool);
    uint32_t (*tick)(void *);
    void (*poll)(void *);
} key_sd_bus;
typedef struct {
    key_sd_bus bus;
    void *context;
    uint64_t sectors;
    uint32_t deadline, exchanges;
    uint8_t csd[16], cid[16];
    bool ready, block_addressed;
} key_sd_readonly;
enum { KEY_SD_OK=0, KEY_SD_ARGUMENT=-1, KEY_SD_IO=-2,
       KEY_SD_TIMEOUT=-3, KEY_SD_PROTOCOL=-4, KEY_SD_CRC=-5 };
KEY_SD_API int key_sd_csd_sectors(const uint8_t csd[16], bool block_addressed, uint64_t *sectors);
KEY_SD_API int key_sd_readonly_init(key_sd_readonly *, const key_sd_bus *, void *);
/* Failed reads clear the entire output. A fault invalidates readiness; initialize
 * again before retrying. Caller owns one 512-byte buffer. */
KEY_SD_API int key_sd_readonly_read(key_sd_readonly *, uint64_t lba, uint8_t out[512]);
#endif
