#ifndef HOST_STM32_HAL_H
#define HOST_STM32_HAL_H
#include <stdint.h>
typedef struct { uint32_t IDR; } GPIO_TypeDef;
typedef struct { uint32_t Pin, Mode, Pull, Speed; } GPIO_InitTypeDef;
typedef enum { GPIO_PIN_RESET=0, GPIO_PIN_SET=1 } GPIO_PinState;
extern GPIO_TypeDef host_gpioa, host_gpioc;
#define GPIOA (&host_gpioa)
#define GPIOC (&host_gpioc)
#define GPIO_PIN_0 0x0001u
#define GPIO_PIN_13 0x2000u
#define GPIO_MODE_INPUT 0u
#define GPIO_PULLDOWN 2u
void host_clock(unsigned);
void host_remap(unsigned);
#define __HAL_RCC_GPIOA_CLK_ENABLE() host_clock(1)
#define __HAL_RCC_GPIOC_CLK_ENABLE() host_clock(4)
#define __HAL_RCC_AFIO_CLK_ENABLE() host_clock(8)
#define __HAL_RCC_PWR_CLK_ENABLE() host_clock(16)
#define __HAL_AFIO_REMAP_SWJ_NOJTAG() host_remap(2)
#define __HAL_AFIO_REMAP_SWJ_DISABLE() host_remap(4)
void HAL_GPIO_Init(GPIO_TypeDef *, GPIO_InitTypeDef *);
GPIO_PinState HAL_GPIO_ReadPin(GPIO_TypeDef *, uint16_t);
uint32_t HAL_GetTick(void);
void HAL_MspInit(void);
#endif
