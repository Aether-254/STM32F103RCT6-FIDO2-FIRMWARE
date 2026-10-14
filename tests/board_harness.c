#include "board_keys.h"
#include "stm32f1xx_hal.h"
#include <stddef.h>
#define API __declspec(dllexport)
GPIO_TypeDef host_gpioa, host_gpioc;
static uint32_t clocks, remap, configured_a, configured_c, bad_config;
void host_clock(unsigned mask) { clocks |= mask; }
void host_remap(unsigned value) { remap = value; }
void HAL_GPIO_Init(GPIO_TypeDef *port, GPIO_InitTypeDef *gpio) {
    if (gpio->Mode != GPIO_MODE_INPUT || gpio->Pull != GPIO_PULLDOWN) bad_config++;
    if (port == GPIOA) configured_a |= gpio->Pin;
    else if (port == GPIOC) configured_c |= gpio->Pin;
    else bad_config++;
}
GPIO_PinState HAL_GPIO_ReadPin(GPIO_TypeDef *port, uint16_t pin) {
    return port->IDR & pin ? GPIO_PIN_SET : GPIO_PIN_RESET;
}
API void board_test_init(void) {
    host_gpioa.IDR = host_gpioc.IDR = clocks = remap = configured_a = configured_c = bad_config = 0;
    HAL_MspInit(); board_keys_init();
}
API void board_test_levels(uint32_t a, uint32_t c) { host_gpioa.IDR = a; host_gpioc.IDR = c; }
API void board_test_poll(void) { board_keys_poll(); }
API int board_test_pressed(void) { return board_keys_pressed(NULL); }
API uint32_t board_test_info(unsigned which) {
    switch (which) {
        case 0:return clocks; case 1:return remap; case 2:return configured_a;
        case 3:return configured_c; case 4:return bad_config;
        case 5:return board_keys_snapshot.magic; case 6:return board_keys_snapshot.sequence;
        case 7:return board_keys_snapshot.tick; case 8:return board_keys_snapshot.raw_mask;
        case 9:return board_keys_snapshot.key1_raw_rises; case 10:return board_keys_snapshot.key2_raw_rises;
        default:return 0;
    }
}
