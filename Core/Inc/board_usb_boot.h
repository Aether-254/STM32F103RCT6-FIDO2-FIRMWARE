#ifndef BOARD_USB_BOOT_H
#define BOARD_USB_BOOT_H
/* Embedfire MINI only: fixed R48 1k pull-up to 3V3 on PA12 (USB D+).
 * Boot-time detach candidate, BEFORE USBD/PCD init and IRQ enable, after HAL
 * tick/clock init. Not a runtime disconnect API. Holds USB in peripheral reset,
 * drives only PA12 low/open-drain for 100ms, then releases it to floating input.
 * Never drives D+ high, changes PA13/PA14, toggles MCU reset or accesses SD.
 * Electrical detach/re-enumeration effectiveness requires real host testing. */
void board_usb_boot_disconnect(void);
#endif
