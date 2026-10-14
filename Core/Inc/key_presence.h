#ifndef KEY_PRESENCE_H
#define KEY_PRESENCE_H
#include <stdbool.h>
#include <stdint.h>
#define KEY_PRESENCE_DEBOUNCE_MS 25u
#define KEY_PRESENCE_HOLD_MS 1000u
#define KEY_PRESENCE_MAX_SAMPLE_GAP_MS 100u
#define KEY_PRESENCE_TIMEOUT_MS 30000u
typedef enum {
    KEY_PRESENCE_IDLE, KEY_PRESENCE_WAIT_RELEASE, KEY_PRESENCE_WAIT_PRESS,
    KEY_PRESENCE_APPROVED, KEY_PRESENCE_CANCELLED, KEY_PRESENCE_TIMED_OUT
} key_presence_status;
typedef struct {
    uint32_t cid, generation, started, changed, sampled;
    bool raw_pressed;
    key_presence_status status;
} key_presence;
/* Foreground only. Inputs must be actual sampled/normalized physical buttons;
 * host harness input is not production presence. No pre-request cached UP. */
void key_presence_reset(key_presence *state);
bool key_presence_begin(key_presence *state, uint32_t cid, uint32_t generation,
                        bool raw_pressed, uint32_t now);
key_presence_status key_presence_sample(key_presence *state, bool raw_pressed, uint32_t now);
/* Multi-input adapter: released means ALL required inputs are released;
 * confirmed means the required combination is down. At begin, pass true if
 * ANY required input is already down. Both flags true is invalid/fail closed. */
key_presence_status key_presence_sample_inputs(key_presence *state, bool released,
                                              bool confirmed, uint32_t now);
/* Read-only UI progress in milliseconds, 0..1000. A stalled sampler cannot
 * authorize or report completion. Sensor faults must cancel the request or
 * revoke backend readiness, NEVER be fabricated as a physical release. */
uint32_t key_presence_progress(const key_presence *state, uint32_t now);
bool key_presence_cancel(key_presence *state, uint32_t cid, uint32_t generation);
/* Consumes exactly once, checks identity and timeout even after approval. */
bool key_presence_consume(key_presence *state, uint32_t cid, uint32_t generation, uint32_t now);
#endif
