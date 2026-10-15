#ifndef KEY_LCD_H
#define KEY_LCD_H
#include "key_crypto.h"
#include <stdbool.h>
#define KEY_LCD_WIDTH 240u
#define KEY_LCD_HEIGHT 320u
#define KEY_LCD_ARGUMENT (-1)
#define KEY_LCD_IO (-2)
#define KEY_LCD_UNSUPPORTED (-3)
typedef struct {
    int (*write)(void *, bool data, uint16_t value);
    int (*read)(void *, uint16_t *value);
    void (*delay_ms)(void *, uint32_t ms);
    void (*service)(void *);
} key_lcd_bus;
typedef struct {
    key_lcd_bus bus;
    void *context;
    uint16_t controller;
    uint8_t id04[4], idd3[4];
    bool ready;
} key_lcd;
/* Serialized foreground 8080-16 bus. Callbacks must be bounded; service must
 * not reenter the driver. Does not touch SD, settings, credentials or consent.
 * Probes 04/D3 before initialization. Only verified 9341 ID is initialized;
 * 8552/ST7789V is identified but deliberately unsupported for display setup.
 * Unknown IDs never receive reset, sleep-out, pixel-format or display-on.
 * No whole-screen RAM framebuffer. Coordinate arguments are checked, not clipped. */
KEY_CRYPTO_API int key_lcd_init(key_lcd *, const key_lcd_bus *, void *);
KEY_CRYPTO_API int key_lcd_fill(key_lcd *, uint16_t x, uint16_t y,
    uint16_t width, uint16_t height, uint16_t rgb565);
#endif
