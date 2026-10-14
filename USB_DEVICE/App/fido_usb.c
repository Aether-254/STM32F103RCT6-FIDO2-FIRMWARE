#include "fido_usb.h"
#include "ctaphid.h"
#include "ctap_dispatch.h"
#include "usbd_customhid.h"
#include <string.h>

extern USBD_HandleTypeDef hUsbDeviceFS;
static ctaphid_state transport;
static uint8_t rx_queue[16][64];
static volatile uint8_t head, tail;
static volatile uint32_t reset_epoch;
static uint32_t seen_epoch;
static bool initialized, inflight;
static uint32_t inflight_ticket;
static uint8_t tx_report[64];
static const ctaphid_jobs *configured_jobs;
static void *configured_context;
volatile uint32_t fido_usb_rx_overflows;

/* Single producer in USB interrupt; consumer owns tail in foreground. */
void fido_usb_receive(const uint8_t report[64]) {
    uint8_t next=(uint8_t)((head+1u)%16u);
    if (next==tail) { fido_usb_rx_overflows++; reset_epoch++; return; }
    memcpy(rx_queue[head],report,64); __DMB(); head=next;
}
void fido_usb_reset(void) { reset_epoch++; }
bool fido_usb_bind_jobs(const ctaphid_jobs *jobs, void *context) {
    if (jobs && (!jobs->begin || !jobs->poll || !jobs->cancel)) return false;
    if (initialized && !ctaphid_set_jobs(&transport,jobs,context)) return false;
    configured_jobs=jobs; configured_context=context; return true;
}

void fido_usb_poll(void) {
    uint32_t irq=__get_PRIMASK(); __disable_irq();
    bool was_initialized=initialized;
    bool reinitialize=!initialized || seen_epoch!=reset_epoch;
    if (reinitialize) {
        tail=head; seen_epoch=reset_epoch; inflight=false; initialized=true;
    }
    if (!irq) __enable_irq();
    /* Job cleanup may touch storage/crypto: never run it with IRQs disabled or
     * from the USB disconnect ISR. Only foreground owns transport/job state. */
    if (reinitialize) {
        if (was_initialized) ctaphid_dispose(&transport);
        ctaphid_init(&transport,ctap_dispatch);
        (void)ctaphid_set_jobs(&transport,configured_jobs,configured_context);
    }
    irq=__get_PRIMASK(); __disable_irq();
    USBD_CUSTOM_HID_HandleTypeDef *hid=hUsbDeviceFS.pClassData;
    bool configured=hUsbDeviceFS.dev_state==USBD_STATE_CONFIGURED && hid;
    bool completed=configured && inflight && hid->state==CUSTOM_HID_IDLE;
    if (!irq) __enable_irq();
    if (!configured || seen_epoch!=reset_epoch) return;
    if (completed) {
        ctaphid_ack(&transport,inflight_ticket); inflight=false;
    }
    for (unsigned i=0; i<16; i++) {
        uint8_t p[64];
        irq=__get_PRIMASK(); __disable_irq();
        bool available=tail!=head;
        if (available) { memcpy(p,rx_queue[tail],64); tail=(uint8_t)((tail+1u)%16u); }
        if (!irq) __enable_irq();
        if (seen_epoch!=reset_epoch) return; /* Cancel in next foreground reset. */
        if (!available) break;
        ctaphid_receive(&transport,p,64,HAL_GetTick());
    }
    if (seen_epoch!=reset_epoch) return;
    ctaphid_tick(&transport,HAL_GetTick());
    /* A reset/overflow may discard our ticket while USB still owns an old
     * buffer. Never overwrite tx_report while that transfer is busy. Protect
     * class-data lifetime against disconnect interrupts during submission. */
    irq=__get_PRIMASK(); __disable_irq();
    hid=hUsbDeviceFS.pClassData;
    if (seen_epoch==reset_epoch && hUsbDeviceFS.dev_state==USBD_STATE_CONFIGURED &&
        hid && hid->state==CUSTOM_HID_IDLE && !inflight &&
        ctaphid_peek(&transport,tx_report,&inflight_ticket)) {
        if (USBD_CUSTOM_HID_SendReport(&hUsbDeviceFS,tx_report,64)==USBD_OK) inflight=true;
    }
    if (!irq) __enable_irq();
}
