/* Host-only USB/HAL facade. Production uses the ST middleware header. */
#ifndef HOST_USBD_CUSTOMHID_H
#define HOST_USBD_CUSTOMHID_H
#include <stddef.h>
#include <stdint.h>
#define USBD_STATE_CONFIGURED 3
#define CUSTOM_HID_IDLE 0
#define CUSTOM_HID_BUSY 1
#define USBD_OK 0
#define USBD_FAIL 2
typedef struct { uint8_t state; } USBD_CUSTOM_HID_HandleTypeDef;
typedef struct { uint8_t dev_state; void *pClassData; } USBD_HandleTypeDef;
uint32_t __get_PRIMASK(void);
void __disable_irq(void);
void __enable_irq(void);
void __DMB(void);
uint32_t HAL_GetTick(void);
uint8_t USBD_CUSTOM_HID_SendReport(USBD_HandleTypeDef *, uint8_t *, uint16_t);
#endif
