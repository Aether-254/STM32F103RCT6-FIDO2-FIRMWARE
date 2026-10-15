#ifndef HOST_USB_BOOT_HAL_H
#define HOST_USB_BOOT_HAL_H
#include <stdint.h>
typedef struct { uint32_t dummy; } GPIO_TypeDef;
typedef struct { uint32_t Pin, Mode, Pull, Speed; } GPIO_InitTypeDef;
typedef enum { GPIO_PIN_RESET=0,GPIO_PIN_SET=1 } GPIO_PinState;
extern GPIO_TypeDef usb_boot_gpioa;
#define GPIOA (&usb_boot_gpioa)
#define GPIO_PIN_12 (1u<<12)
#define GPIO_MODE_OUTPUT_OD 1u
#define GPIO_MODE_INPUT 2u
#define GPIO_NOPULL 0u
#define GPIO_SPEED_FREQ_LOW 2u
void usb_boot_event(uint32_t,uint32_t);
#define __HAL_RCC_GPIOA_CLK_ENABLE() usb_boot_event(1,0)
#define __HAL_RCC_USB_FORCE_RESET() usb_boot_event(2,0)
#define __HAL_RCC_USB_RELEASE_RESET() usb_boot_event(7,0)
void HAL_GPIO_WritePin(GPIO_TypeDef *,uint16_t,GPIO_PinState);
void HAL_GPIO_Init(GPIO_TypeDef *,GPIO_InitTypeDef *);
void HAL_Delay(uint32_t);
#endif
