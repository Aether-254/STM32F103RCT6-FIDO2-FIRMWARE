#include "usbd_customhid.h"
#include "fido_usb.h"
#include <string.h>
#ifdef _WIN32
#define API __declspec(dllexport)
#else
#define API
#endif
USBD_HandleTypeDef hUsbDeviceFS;
static USBD_CUSTOM_HID_HandleTypeDef hid;
static uint32_t now, masked, send_count;
static int reject_send;
static uint8_t *retained;
static unsigned job_cancelled, callback_masked, job_done;
static bool job_active;
static size_t job_begin(void *ctx, uint32_t cid, const uint8_t *p, size_t n,
                        uint32_t t, uint8_t *out, size_t cap) {
    (void)ctx; (void)cid; (void)p; (void)n; (void)t; (void)out; (void)cap;
    callback_masked|=masked; job_active=true; return 0;
}
static size_t job_poll(void *ctx, uint32_t t, uint8_t *out, size_t cap, uint8_t *status) {
    (void)ctx; (void)t; (void)cap; callback_masked|=masked; *status=2;
    if (job_done) { job_active=false; out[0]=0x27; return 1; } return 0;
}
static void job_cancel(void *ctx) {
    (void)ctx; callback_masked|=masked; job_cancelled++; job_active=false;
}
static const ctaphid_jobs jobs={job_begin,job_poll,job_cancel,NULL};
uint32_t __get_PRIMASK(void) { return masked; }
void __disable_irq(void) { masked=1; }
void __enable_irq(void) { masked=0; }
void __DMB(void) { }
uint32_t HAL_GetTick(void) { return now; }
uint8_t USBD_CUSTOM_HID_SendReport(USBD_HandleTypeDef *d, uint8_t *p, uint16_t n) {
    if (reject_send || n!=64 || !d->pClassData || hid.state!=CUSTOM_HID_IDLE)
        return USBD_FAIL;
    retained=p; hid.state=CUSTOM_HID_BUSY; send_count++; return USBD_OK;
}
API void usb_reset_test(void) {
    hid.state=CUSTOM_HID_IDLE; now=0; masked=0; send_count=0;
    reject_send=0; retained=NULL; fido_usb_rx_overflows=0;
    hUsbDeviceFS.dev_state=USBD_STATE_CONFIGURED; hUsbDeviceFS.pClassData=&hid;
    fido_usb_reset(); fido_usb_poll();
    (void)fido_usb_bind_jobs(NULL,NULL);
}
API void usb_receive(const uint8_t *p) { fido_usb_receive(p); }
API void usb_poll(uint32_t t) { now=t; fido_usb_poll(); }
API void usb_complete(void) { hid.state=CUSTOM_HID_IDLE; }
API void usb_read(uint8_t *p) { if(retained) memcpy(p,retained,64); else memset(p,0,64); }
API unsigned usb_sent(void) { return send_count; }
API unsigned usb_overflows(void) { return fido_usb_rx_overflows; }
API unsigned usb_masked(void) { return masked; }
API void usb_reject(int reject) { reject_send=reject; }
API void usb_disconnect(void) {
    hUsbDeviceFS.dev_state=0; hUsbDeviceFS.pClassData=NULL; fido_usb_reset();
}
API void usb_reconnect(void) {
    hid.state=CUSTOM_HID_IDLE;
    hUsbDeviceFS.dev_state=USBD_STATE_CONFIGURED; hUsbDeviceFS.pClassData=&hid;
    fido_usb_reset();
}
API int usb_jobs_enable(void) {
    job_cancelled=callback_masked=job_done=0; job_active=false;
    return fido_usb_bind_jobs(&jobs,NULL);
}
API int usb_jobs_disable(void) { return fido_usb_bind_jobs(NULL,NULL); }
API void usb_job_finish(void) { job_done=1; }
API unsigned usb_job_cancelled(void) { return job_cancelled; }
API unsigned usb_callback_masked(void) { return callback_masked; }
API int usb_job_active(void) { return job_active; }
