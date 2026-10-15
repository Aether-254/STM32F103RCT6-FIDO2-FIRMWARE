#ifndef KEY_UI_H
#define KEY_UI_H
#include "key_crypto.h"
#include <stdbool.h>
/* Navigation only. This module cannot authorize, write storage or set a clock.
 * A1 release=next; A1 hold 700ms=enter; A2 release=back. Both keys suppress
 * navigation until released. Startup-held keys are similarly quarantined.
 * Tick is an unsigned wrapping millisecond counter, not an RTC timestamp. */
typedef struct {
    uint32_t changed_at, pressed_at;
    uint8_t candidate, stable, selected, page;
    bool armed, consumed;
} key_ui;
typedef int (*key_ui_rect)(void *, uint16_t, uint16_t, uint16_t, uint16_t, uint16_t);
KEY_CRYPTO_API void key_ui_init(key_ui *, uint32_t now);
KEY_CRYPTO_API bool key_ui_poll(key_ui *, uint32_t now, uint8_t raw_keys);
/* Renders truthful no-SD diagnostic UI, never fake OTP/time or credentials.
 * Rect callback is foreground-only, must not reenter UI. No framebuffer/heap.
 * Returns first drawing failure. Font is an original tiny uppercase bitmap. */
KEY_CRYPTO_API int key_ui_render(const key_ui *, key_ui_rect, void *);
/* On root-selection-only changes, repaint just the old/new menu rows.
 * Requires the previous frame to have rendered successfully. */
KEY_CRYPTO_API int key_ui_render_update(const key_ui *, const key_ui *, key_ui_rect, void *);
#endif
