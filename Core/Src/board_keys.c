#include "board_keys.h"
#include "stm32f1xx_hal.h"
volatile board_keys_diagnostics board_keys_snapshot;
static bool initialized;
void board_keys_init(void) {
    GPIO_InitTypeDef gpio = {0};
    __HAL_RCC_GPIOA_CLK_ENABLE(); __HAL_RCC_GPIOC_CLK_ENABLE();
    gpio.Mode = GPIO_MODE_INPUT; gpio.Pull = GPIO_PULLDOWN;
    gpio.Pin = GPIO_PIN_0; HAL_GPIO_Init(GPIOA, &gpio);
    gpio.Pin = GPIO_PIN_13; HAL_GPIO_Init(GPIOC, &gpio);
    board_keys_snapshot.magic = 0;
    board_keys_snapshot.sequence = board_keys_snapshot.tick = board_keys_snapshot.raw_mask = 0;
    board_keys_snapshot.key1_raw_rises = board_keys_snapshot.key2_raw_rises = 0;
    initialized = true; board_keys_snapshot.magic = 0x4B455931u;
    board_keys_poll();
}
void board_keys_poll(void) {
    if (!initialized) return;
    uint32_t mask = (HAL_GPIO_ReadPin(GPIOA, GPIO_PIN_0) == GPIO_PIN_SET ? 1u : 0u) |
                    (HAL_GPIO_ReadPin(GPIOC, GPIO_PIN_13) == GPIO_PIN_SET ? 2u : 0u);
    ++board_keys_snapshot.sequence; /* Odd during update; debugger can double-read. */
    uint32_t rises = mask & ~board_keys_snapshot.raw_mask;
    if (rises & 1u) ++board_keys_snapshot.key1_raw_rises;
    if (rises & 2u) ++board_keys_snapshot.key2_raw_rises;
    board_keys_snapshot.raw_mask = mask;
    board_keys_snapshot.tick = HAL_GetTick();
    ++board_keys_snapshot.sequence;
}
bool board_keys_pressed(void *context) {
    (void)context;
    return initialized && board_keys_snapshot.raw_mask != 0;
}
/* Raw diagnostic rises are not authorization tokens. Request-bound continuous
 * one-second consent is enforced by key_presence. Do not bind this any-key
 * diagnostic predicate as the explicitly enabled BOTH-key fallback. */
