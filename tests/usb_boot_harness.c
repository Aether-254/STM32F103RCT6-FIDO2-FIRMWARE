#include "stm32f1xx_hal.h"
#include "board_usb_boot.h"
#define API __declspec(dllexport)
GPIO_TypeDef usb_boot_gpioa;
static uint32_t trace[32][2], count, bad;
void usb_boot_event(uint32_t event,uint32_t value) {
    if(count>=32) { ++bad; return; }
    trace[count][0]=event;trace[count++][1]=value;
}
void HAL_GPIO_WritePin(GPIO_TypeDef *p,uint16_t pin,GPIO_PinState level) {
    if(p!=GPIOA || pin!=GPIO_PIN_12 || level!=GPIO_PIN_RESET) ++bad;
    usb_boot_event(3,pin);
}
void HAL_GPIO_Init(GPIO_TypeDef *p,GPIO_InitTypeDef *gpio) {
    if(p!=GPIOA || gpio->Pin!=GPIO_PIN_12 || gpio->Pull!=GPIO_NOPULL) ++bad;
    if(gpio->Mode==GPIO_MODE_OUTPUT_OD) {
        if(gpio->Speed!=GPIO_SPEED_FREQ_LOW) ++bad;
        usb_boot_event(4,gpio->Pin);
    } else if(gpio->Mode==GPIO_MODE_INPUT) usb_boot_event(6,gpio->Pin);
    else ++bad;
}
void HAL_Delay(uint32_t ms) { usb_boot_event(5,ms); }
API void usb_boot_test(void) { count=bad=0;board_usb_boot_disconnect(); }
API uint32_t usb_boot_info(unsigned n,unsigned field) {
    if(n==32) return count;
    if(n==33) return bad;
    return n<count && field<2 ? trace[n][field] : UINT32_MAX;
}
