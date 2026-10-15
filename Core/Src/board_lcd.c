#include "board_lcd.h"
#include "board_keys.h"
#include "key_lcd.h"
#include "fido_usb.h"
#include "stm32f1xx_hal.h"
#include <string.h>
volatile board_lcd_diagnostics board_lcd_snapshot;
static key_lcd panel;
static uint32_t last_poll;
static bool output;
/* Embedfire MINI 8080-16: PB0..15=data, PC4=CS, PC5=RD, PC6=WR,
 * PC7=DC, PD2=active-low backlight. LCD NRST is shared: never toggle it here.
 * HAL_MspInit must preserve SWD and disable only JTAG (PB3/PB4 used as data). */
static void settle(void) {
    for (volatile unsigned n = 0; n < 16; ++n) __NOP();
}
static void direction(bool drive) {
    if (output == drive) return;
    GPIOB->CRL = drive ? 0x22222222u : 0x44444444u;
    GPIOB->CRH = drive ? 0x22222222u : 0x44444444u;
    output = drive;
    settle();
}
static int write_word(void *context, bool data, uint16_t value) {
    (void)context;
    GPIOC->BSRR = GPIO_PIN_4 | GPIO_PIN_5 | GPIO_PIN_6;
    direction(true);
    if (data) GPIOC->BSRR = GPIO_PIN_7;
    else GPIOC->BRR = GPIO_PIN_7;
    GPIOB->ODR = value;
    GPIOC->BRR = GPIO_PIN_4;
    settle();
    GPIOC->BRR = GPIO_PIN_6;
    settle();
    GPIOC->BSRR = GPIO_PIN_6;
    settle();
    GPIOC->BSRR = GPIO_PIN_4;
    ++board_lcd_snapshot.written_words;
    return 0;
}
static int read_word(void *context, uint16_t *value) {
    (void)context;
    GPIOC->BSRR = GPIO_PIN_4 | GPIO_PIN_5 | GPIO_PIN_6 | GPIO_PIN_7;
    direction(false);
    GPIOC->BRR = GPIO_PIN_4;
    settle();
    GPIOC->BRR = GPIO_PIN_5;
    settle();
    *value = (uint16_t)GPIOB->IDR;
    GPIOC->BSRR = GPIO_PIN_5;
    settle();
    GPIOC->BSRR = GPIO_PIN_4;
    ++board_lcd_snapshot.read_words;
    return 0;
}
static void service(void *context) {
    (void)context;
    board_keys_poll();
    fido_usb_poll();
}
static void delay_ms(void *context, uint32_t ms) {
    for (uint32_t i = 0; i < ms; ++i) {
        HAL_Delay(1);
        service(context);
    }
}
static int rect(unsigned x, unsigned y, unsigned w, unsigned h, uint16_t color) {
    return key_lcd_fill(&panel, (uint16_t)x, (uint16_t)y, (uint16_t)w, (uint16_t)h, color);
}
static int hex_digit(unsigned x, unsigned y, unsigned digit) {
    static const uint8_t segments[16] = {
        0x3f,0x06,0x5b,0x4f,0x66,0x6d,0x7d,0x07,
        0x7f,0x6f,0x77,0x7c,0x39,0x5e,0x79,0x71};
    static const uint8_t boxes[7][4] = {
        {3,0,14,3},{17,3,3,14},{17,20,3,14},{3,34,14,3},
        {0,20,3,14},{0,3,3,14},{3,17,14,3}};
    for (unsigned s = 0; s < 7; ++s)
        if (segments[digit & 15] & (1u << s))
            if (rect(x + boxes[s][0], y + boxes[s][1], boxes[s][2], boxes[s][3], 0xe50f))
                return KEY_LCD_IO;
    return 0;
}
static int pattern(void) {
    if (rect(0,0,320,240,0x18c3)) return KEY_LCD_IO;
    for (unsigned i = 0; i < 4; ++i)
        if (hex_digit(102 + 30*i,24,panel.controller >> (12-4*i))) return KEY_LCD_IO;
    if (rect(16,84,96,28,0xf800) || rect(112,84,96,28,0x07e0) ||
        rect(208,84,96,28,0x001f)) return KEY_LCD_IO;
    for (unsigned i = 0; i < 16; ++i) {
        unsigned v = i * 31 / 15;
        uint16_t gray = (uint16_t)((v << 11) | ((v * 2) << 5) | v);
        if (rect(16+i*18,208,18,16,gray)) return KEY_LCD_IO;
    }
    return 0;
}
void board_lcd_diagnose(void) {
    memset((void *)&board_lcd_snapshot,0,sizeof(board_lcd_snapshot));
    board_lcd_snapshot.sequence = 1;
    board_lcd_snapshot.render_result = KEY_LCD_ARGUMENT;
    __HAL_RCC_GPIOB_CLK_ENABLE(); __HAL_RCC_GPIOC_CLK_ENABLE();
    __HAL_RCC_GPIOD_CLK_ENABLE();
    HAL_GPIO_WritePin(GPIOC,GPIO_PIN_4|GPIO_PIN_5|GPIO_PIN_6|GPIO_PIN_7,GPIO_PIN_SET);
    HAL_GPIO_WritePin(GPIOD,GPIO_PIN_2,GPIO_PIN_SET);
    GPIO_InitTypeDef gpio = {0};
    gpio.Mode=GPIO_MODE_OUTPUT_PP; gpio.Speed=GPIO_SPEED_FREQ_LOW;
    gpio.Pin=GPIO_PIN_4|GPIO_PIN_5|GPIO_PIN_6|GPIO_PIN_7; HAL_GPIO_Init(GPIOC,&gpio);
    gpio.Pin=GPIO_PIN_2; HAL_GPIO_Init(GPIOD,&gpio);
    /* Release the bus before asserting any LCD read strobe. */
    GPIOB->CRL=0x44444444u; GPIOB->CRH=0x44444444u; output=false;
    key_lcd_bus bus={write_word,read_word,delay_ms,service};
    int rc=key_lcd_init(&panel,&bus,NULL);
    board_lcd_snapshot.init_result=rc;
    board_lcd_snapshot.controller=panel.controller;
    for (unsigned i=0;i<4;++i) {
        board_lcd_snapshot.id04=(board_lcd_snapshot.id04<<8)|panel.id04[i];
        board_lcd_snapshot.idd3=(board_lcd_snapshot.idd3<<8)|panel.idd3[i];
    }
    if (!rc) {
        board_lcd_snapshot.render_result=pattern();
        if (!board_lcd_snapshot.render_result) HAL_GPIO_WritePin(GPIOD,GPIO_PIN_2,GPIO_PIN_RESET);
    }
    board_lcd_snapshot.magic=0x4c434431u;
    board_lcd_snapshot.sequence=2;
    board_lcd_snapshot.key_mask=UINT32_MAX;
    last_poll=HAL_GetTick();
}
void board_lcd_poll(void) {
    uint32_t now=HAL_GetTick();
    if (!panel.ready || board_lcd_snapshot.render_result || (uint32_t)(now-last_poll)<50) return;
    last_poll=now;
    uint32_t keys=board_keys_snapshot.raw_mask;
    if (keys==board_lcd_snapshot.key_mask) return;
    ++board_lcd_snapshot.sequence;
    /* Raw navigation indicators only, never authentication or fallback consent. */
    int rc=rect(16,150,136,32,(keys&1)?0xe50f:0x3186);
    if (!rc) rc=rect(168,150,136,32,(keys&2)?0xe50f:0x3186);
    board_lcd_snapshot.render_result=rc;
    board_lcd_snapshot.key_mask=keys;
    board_lcd_snapshot.tick=now;
    ++board_lcd_snapshot.sequence;
}
