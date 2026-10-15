#include "board_usb_boot.h"
#include "stm32f1xx_hal.h"
void board_usb_boot_disconnect(void) {
    __HAL_RCC_GPIOA_CLK_ENABLE();
    __HAL_RCC_USB_FORCE_RESET();
    /* Preload the low latch before enabling the open-drain output. */
    HAL_GPIO_WritePin(GPIOA,GPIO_PIN_12,GPIO_PIN_RESET);
    GPIO_InitTypeDef gpio={0};
    gpio.Pin=GPIO_PIN_12;
    gpio.Mode=GPIO_MODE_OUTPUT_OD;
    gpio.Pull=GPIO_NOPULL;
    gpio.Speed=GPIO_SPEED_FREQ_LOW;
    HAL_GPIO_Init(GPIOA,&gpio);
    HAL_Delay(100);
    /* Return pin ownership before USBD_Init initializes USB. The external
     * resistor raises D+; do not source current against a host reset. */
    gpio.Mode=GPIO_MODE_INPUT;
    HAL_GPIO_Init(GPIOA,&gpio);
    __HAL_RCC_USB_RELEASE_RESET();
}
