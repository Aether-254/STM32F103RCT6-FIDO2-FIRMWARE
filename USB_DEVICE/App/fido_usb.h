#ifndef FIDO_USB_H
#define FIDO_USB_H
#include <stdint.h>
#include "ctaphid.h"
void fido_usb_poll(void);
/* Foreground-only optional credential-job binding. No jobs enabled by default.
 * Returns false if a transaction is active; callbacks survive USB reinit. */
bool fido_usb_bind_jobs(const ctaphid_jobs *jobs, void *context);
void fido_usb_receive(const uint8_t report[64]);
void fido_usb_reset(void);
extern volatile uint32_t fido_usb_rx_overflows;
#endif
