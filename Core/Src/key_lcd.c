#include "key_lcd.h"
#include <string.h>
static int write_word(key_lcd *lcd, bool data, uint16_t word) {
    if (lcd->bus.write(lcd->context, data, word)) {
        lcd->ready = false;
        return KEY_LCD_IO;
    }
    return 0;
}
static int identify(key_lcd *lcd, uint8_t command, uint8_t bytes[4]) {
    if (write_word(lcd, false, command)) return KEY_LCD_IO;
    for (unsigned i = 0; i < 4; ++i) {
        uint16_t value;
        if (lcd->bus.read(lcd->context, &value)) return KEY_LCD_IO;
        /* Register bytes use D7:0; upper bus bits are don't-care, unlike pixels. */
        bytes[i] = (uint8_t)value;
    }
    return 0;
}
int key_lcd_init(key_lcd *lcd, const key_lcd_bus *bus, void *context) {
    if (!lcd) return KEY_LCD_ARGUMENT;
    const key_lcd_bus copy = bus ? *bus : (key_lcd_bus){0};
    memset(lcd, 0, sizeof(*lcd));
    if (!copy.write || !copy.read || !copy.delay_ms)
        return KEY_LCD_ARGUMENT;
    lcd->bus = copy; lcd->context = context;
    if (identify(lcd, 0x04, lcd->id04)) return KEY_LCD_IO;
    if (lcd->id04[2] == 0x85 && lcd->id04[3] == 0x52) {
        lcd->controller = 0x8552;
        return KEY_LCD_UNSUPPORTED;
    }
    if (identify(lcd, 0xd3, lcd->idd3)) return KEY_LCD_IO;
    if (lcd->idd3[1] != 0 || lcd->idd3[2] != 0x93 || lcd->idd3[3] != 0x41)
        return KEY_LCD_UNSUPPORTED;
    lcd->controller = 0x9341;
    if (write_word(lcd, false, 0x01)) return KEY_LCD_IO; /* LCD SWRESET, not MCU NRST. */
    lcd->bus.delay_ms(context, 150);
    if (write_word(lcd, false, 0x11)) return KEY_LCD_IO;
    lcd->bus.delay_ms(context, 120);
    if (write_word(lcd, false, 0x3a) || write_word(lcd, true, 0x55) ||
        write_word(lcd, false, 0x36) || write_word(lcd, true, 0x28) ||
        write_word(lcd, false, 0x29)) return KEY_LCD_IO;
    lcd->ready = true;
    return 0;
}
static int axis(key_lcd *lcd, uint8_t command, uint16_t start, uint16_t end) {
    return write_word(lcd, false, command) || write_word(lcd, true, start >> 8) ||
        write_word(lcd, true, start & 255) || write_word(lcd, true, end >> 8) ||
        write_word(lcd, true, end & 255) ? KEY_LCD_IO : 0;
}
int key_lcd_fill(key_lcd *lcd, uint16_t x, uint16_t y,
    uint16_t width, uint16_t height, uint16_t rgb565) {
    if (!lcd || !lcd->ready || x >= KEY_LCD_WIDTH || y >= KEY_LCD_HEIGHT ||
        !width || !height || width > KEY_LCD_WIDTH - x || height > KEY_LCD_HEIGHT - y)
        return KEY_LCD_ARGUMENT;
    if (axis(lcd, 0x2a, x, (uint16_t)(x + width - 1)) ||
        axis(lcd, 0x2b, y, (uint16_t)(y + height - 1)) ||
        write_word(lcd, false, 0x2c)) return KEY_LCD_IO;
    uint32_t count = (uint32_t)width * height;
    for (uint32_t i = 0; i < count; ++i) {
        if (write_word(lcd, true, rgb565)) return KEY_LCD_IO;
        if ((i & 127u) == 127u && lcd->bus.service) lcd->bus.service(lcd->context);
    }
    if (lcd->bus.service) lcd->bus.service(lcd->context);
    return 0;
}
