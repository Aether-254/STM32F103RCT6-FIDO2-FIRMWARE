#ifndef BOARD_LCD_H
#define BOARD_LCD_H
#include <stdint.h>
typedef struct {
    uint32_t magic, sequence, controller;
    int32_t init_result, render_result;
    uint32_t id04, idd3, written_words, read_words, key_mask, tick;
} board_lcd_diagnostics;
extern volatile board_lcd_diagnostics board_lcd_snapshot;
/* Opt-in GPIO/LCD diagnostic only. No SD, credentials, RTC or authorization.
 * All GPIOB data pins are owned by the display while this diagnostic is active.
 * Unknown controller: backlight off, no guessed power/gamma initialization. */
void board_lcd_diagnose(void);
void board_lcd_poll(void);
#endif
