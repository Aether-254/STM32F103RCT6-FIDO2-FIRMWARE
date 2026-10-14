#include "key_presence.h"
#include <string.h>
static bool active(const key_presence *s) {
    return s->status==KEY_PRESENCE_WAIT_RELEASE || s->status==KEY_PRESENCE_WAIT_PRESS ||
           s->status==KEY_PRESENCE_APPROVED;
}
static void expire(key_presence *s, uint32_t now) {
    if (active(s) && (uint32_t)(now-s->started)>=KEY_PRESENCE_TIMEOUT_MS)
        s->status=KEY_PRESENCE_TIMED_OUT;
}
void key_presence_reset(key_presence *s) { if (s) memset(s,0,sizeof(*s)); }
bool key_presence_begin(key_presence *s, uint32_t cid, uint32_t generation,
                        bool pressed, uint32_t now) {
    if (!s || !cid || cid==UINT32_MAX || !generation) return false;
    expire(s,now);
    if (active(s)) return false; /* No overwriting a pending authorization. */
    *s=(key_presence){.cid=cid,.generation=generation,.started=now,
                     .changed=now,.sampled=now,.raw_pressed=pressed,.status=KEY_PRESENCE_WAIT_RELEASE};
    return true;
}
key_presence_status key_presence_sample(key_presence *s, bool pressed, uint32_t now) {
    return key_presence_sample_inputs(s,!pressed,pressed,now);
}
key_presence_status key_presence_sample_inputs(key_presence *s, bool released,
                                               bool confirmed, uint32_t now) {
    if (!s) return KEY_PRESENCE_IDLE;
    expire(s,now);
    if (released && confirmed && active(s)) s->status=KEY_PRESENCE_CANCELLED;
    if (!active(s) || s->status==KEY_PRESENCE_APPROVED) return s->status;
    bool pressed=s->status==KEY_PRESENCE_WAIT_RELEASE ? !released : confirmed;
    /* Missing samples cannot serve as evidence of a continuous hold/release. */
    if ((uint32_t)(now-s->sampled)>KEY_PRESENCE_MAX_SAMPLE_GAP_MS) s->changed=now;
    s->sampled=now;
    if (pressed!=s->raw_pressed) { s->raw_pressed=pressed; s->changed=now; }
    if ((uint32_t)(now-s->changed)<KEY_PRESENCE_DEBOUNCE_MS) return s->status;
    if (s->status==KEY_PRESENCE_WAIT_RELEASE && !pressed) s->status=KEY_PRESENCE_WAIT_PRESS;
    else if (s->status==KEY_PRESENCE_WAIT_PRESS && pressed &&
             (uint32_t)(now-s->changed)>=KEY_PRESENCE_HOLD_MS)
        s->status=KEY_PRESENCE_APPROVED;
    return s->status;
}
uint32_t key_presence_progress(const key_presence *s, uint32_t now) {
    if (!s || (uint32_t)(now-s->started)>=KEY_PRESENCE_TIMEOUT_MS) return 0;
    if (s->status==KEY_PRESENCE_APPROVED) return KEY_PRESENCE_HOLD_MS;
    if (s->status!=KEY_PRESENCE_WAIT_PRESS || !s->raw_pressed ||
        (uint32_t)(now-s->sampled)>KEY_PRESENCE_MAX_SAMPLE_GAP_MS) return 0;
    uint32_t elapsed=(uint32_t)(now-s->changed);
    return elapsed<KEY_PRESENCE_HOLD_MS ? elapsed : KEY_PRESENCE_HOLD_MS-1u;
}
bool key_presence_cancel(key_presence *s, uint32_t cid, uint32_t generation) {
    if (!s || !active(s) || s->cid!=cid || s->generation!=generation) return false;
    s->status=KEY_PRESENCE_CANCELLED; return true;
}
bool key_presence_consume(key_presence *s, uint32_t cid, uint32_t generation, uint32_t now) {
    if (!s) return false;
    expire(s,now);
    if (s->status!=KEY_PRESENCE_APPROVED || s->cid!=cid || s->generation!=generation) return false;
    key_presence_reset(s); return true;
}
