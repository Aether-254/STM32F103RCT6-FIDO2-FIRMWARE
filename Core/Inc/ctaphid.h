#ifndef CTAPHID_H
#define CTAPHID_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CTAPHID_PACKET_SIZE 64u
#define CTAPHID_MAX_MESSAGE 4096u
#define CTAPHID_RX_TIMEOUT_MS 3000u
#define CTAPHID_BROADCAST UINT32_MAX
#define CTAPHID_KEEPALIVE_MS 100u
#define CTAPHID_JOB_TIMEOUT_MS 30000u

typedef size_t (*ctaphid_dispatch_fn)(const uint8_t *request, size_t length,
                                    uint8_t *response, size_t capacity);
/* Optional foreground jobs: zero means still pending; nonzero is a complete
 * CTAP response (including status byte). begin borrows RX until completion or
 * cancel. poll MUST be bounded/nonblocking, status 1=processing, 2=UP_NEEDED.
 * cancel must release its borrowed views and revoke authorization promptly. */
typedef struct {
    size_t (*begin)(void *, uint32_t, const uint8_t *, size_t, uint32_t, uint8_t *, size_t);
    size_t (*poll)(void *, uint32_t, uint8_t *, size_t, uint8_t *);
    void (*cancel)(void *);
    /* Optional bounded status selection before timeout cleanup (e.g. excluded
     * credential privacy rule). NULL uses USER_ACTION_TIMEOUT. */
    uint8_t (*timeout_status)(void *);
} ctaphid_jobs;
typedef struct {
    uint32_t cid;
    uint8_t code;
} ctaphid_error;
typedef struct {
    uint8_t rx[CTAPHID_MAX_MESSAGE];
    uint8_t tx[CTAPHID_MAX_MESSAGE];
    uint32_t last_cid, active_cid, rx_started;
    uint16_t rx_length, rx_used, tx_length, tx_used;
    uint8_t rx_command, rx_sequence, tx_command, tx_sequence;
    bool receiving, transmitting;
    ctaphid_error errors[4];
    uint8_t error_head, error_count;
    uint32_t dropped_errors;
    uint8_t pending[CTAPHID_PACKET_SIZE];
    uint32_t ticket_counter, pending_ticket;
    uint16_t pending_bytes;
    bool pending_error;
    ctaphid_dispatch_fn dispatch;
    const ctaphid_jobs *jobs;
    void *job_context;
    uint32_t job_started, keepalive_sent;
    bool executing, keepalive_ready, pending_keepalive;
    uint8_t keepalive_status;
} ctaphid_state;

/* All calls run in the foreground, never directly in a USB interrupt. */
void ctaphid_init(ctaphid_state *s, ctaphid_dispatch_fn dispatch);
/* Configure only while idle. ops/context must outlive the transport. */
bool ctaphid_set_jobs(ctaphid_state *s, const ctaphid_jobs *ops, void *context);
/* Foreground teardown before reinit/disconnect: cancels job and wipes buffers. */
void ctaphid_dispose(ctaphid_state *s);
void ctaphid_receive(ctaphid_state *s, const uint8_t *packet, size_t length, uint32_t now);
void ctaphid_tick(ctaphid_state *s, uint32_t now);
/* Peek is stable until acknowledged. Ack only AFTER successful USB completion.
 * Tickets prevent an in-flight pre-resynchronization completion consuming new data. */
bool ctaphid_peek(ctaphid_state *s, uint8_t packet[64], uint32_t *ticket);
void ctaphid_ack(ctaphid_state *s, uint32_t ticket);
#endif
