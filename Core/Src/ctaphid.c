#include "ctaphid.h"
#include <string.h>

enum { PING=0x81, INIT=0x86, CBOR=0x90, CANCEL=0x91, KEEPALIVE=0xbb, ERROR=0xbf };
enum { INVALID_CMD=1, INVALID_LEN=3, INVALID_SEQ=4, TIMEOUT=5, BUSY=6, INVALID_CID=11 };

static uint32_t get32(const uint8_t *p) {
    return ((uint32_t)p[0]<<24) | ((uint32_t)p[1]<<16) | ((uint32_t)p[2]<<8) | p[3];
}
static void put32(uint8_t *p, uint32_t v) {
    p[0]=(uint8_t)(v>>24); p[1]=(uint8_t)(v>>16); p[2]=(uint8_t)(v>>8); p[3]=(uint8_t)v;
}
static void error(ctaphid_state *s, uint32_t cid, uint8_t code) {
    if (s->error_count == 4) { s->dropped_errors++; return; }
    unsigned i=(s->error_head+s->error_count)%4;
    s->errors[i].cid=cid; s->errors[i].code=code; s->error_count++;
}
static void abort_transaction(ctaphid_state *s) {
    if (s->executing && s->jobs) s->jobs->cancel(s->job_context);
    s->executing=false; s->keepalive_ready=false;
    s->receiving=false; s->transmitting=false;
    s->rx_used=0; s->tx_used=0;
    /* Preserve a pending unrelated error, invalidate only primary data. */
    if (!s->pending_error) s->pending_ticket=0;
    memset(s->rx, 0, sizeof(s->rx)); memset(s->tx, 0, sizeof(s->tx));
}
static void respond(ctaphid_state *s, uint32_t cid, uint8_t cmd, size_t n) {
    s->active_cid=cid; s->tx_command=cmd; s->tx_length=(uint16_t)n;
    s->tx_used=0; s->tx_sequence=0; s->transmitting=true; s->receiving=false;
}
void ctaphid_init(ctaphid_state *s, ctaphid_dispatch_fn dispatch) {
    memset(s,0,sizeof(*s)); s->dispatch=dispatch;
}
bool ctaphid_set_jobs(ctaphid_state *s, const ctaphid_jobs *jobs, void *context) {
    if (!s || s->receiving || s->transmitting || s->executing || s->pending_ticket || s->error_count)
        return false;
    if (jobs && (!jobs->begin || !jobs->poll || !jobs->cancel)) return false;
    s->jobs=jobs; s->job_context=context; return true;
}
void ctaphid_dispose(ctaphid_state *s) {
    if (!s) return;
    abort_transaction(s); memset(s,0,sizeof(*s));
}
static void finish_job(ctaphid_state *s, size_t n) {
    if ((!n || n>sizeof(s->tx)) && s->executing) s->jobs->cancel(s->job_context);
    s->executing=false; s->keepalive_ready=false;
    if (!n || n>sizeof(s->tx)) { memset(s->tx,0,sizeof(s->tx)); s->tx[0]=0x7f; n=1; }
    memset(s->rx,0,sizeof(s->rx));
    /* Preserve already peeked KEEPALIVE: its completion must not consume final
     * response bytes, and normal completion cannot change a peeked report. */
    respond(s,s->active_cid,CBOR,n);
}
void ctaphid_tick(ctaphid_state *s, uint32_t now) {
    if (s->receiving && (uint32_t)(now-s->rx_started)>=CTAPHID_RX_TIMEOUT_MS) {
        uint32_t cid=s->active_cid;
        abort_transaction(s); error(s,cid,TIMEOUT);
    }
    if (s->executing) {
        if ((uint32_t)(now-s->job_started)>=CTAPHID_JOB_TIMEOUT_MS) {
            uint8_t code=s->jobs->timeout_status?s->jobs->timeout_status(s->job_context):0x2f;
            abort_transaction(s); s->tx[0]=code?code:0x2f;
            respond(s,s->active_cid,CBOR,1); return;
        }
        uint8_t status=1;
        size_t n=s->jobs->poll(s->job_context,now,s->tx,sizeof(s->tx),&status);
        if (n) { finish_job(s,n); return; }
        status=status==2?2:1;
        if (status!=s->keepalive_status || (uint32_t)(now-s->keepalive_sent)>=CTAPHID_KEEPALIVE_MS) {
            s->keepalive_ready=true; s->keepalive_sent=now;
        }
        s->keepalive_status=status;
    }
}
static void complete(ctaphid_state *s, uint32_t now) {
    size_t n=s->rx_length;
    if (s->rx_command==PING) {
        memcpy(s->tx,s->rx,n); respond(s,s->active_cid,PING,n);
    } else if (s->rx_command==CBOR) {
        if (!n) { abort_transaction(s); error(s,s->active_cid,INVALID_LEN); return; }
        if (s->jobs) {
            s->receiving=false;
            n=s->jobs->begin(s->job_context,s->active_cid,s->rx,n,now,s->tx,sizeof(s->tx));
            if (!n) {
                s->executing=true; s->job_started=now; s->keepalive_sent=now;
                s->keepalive_status=1; s->keepalive_ready=false; return;
            }
            if (n>sizeof(s->tx)) s->jobs->cancel(s->job_context);
        } else n=s->dispatch ? s->dispatch(s->rx,n,s->tx,sizeof(s->tx)) : 0;
        if (!n || n>sizeof(s->tx)) { s->tx[0]=0x7f; n=1; }
        respond(s,s->active_cid,CBOR,n);
    }
    memset(s->rx,0,sizeof(s->rx));
}
void ctaphid_receive(ctaphid_state *s, const uint8_t *p, size_t length, uint32_t now) {
    if (length!=CTAPHID_PACKET_SIZE || p==NULL) return;
    ctaphid_tick(s,now);
    uint32_t cid=get32(p);
    bool initial=(p[4]&0x80)!=0;
    if (initial && p[4]==CANCEL && (!s->executing || cid!=s->active_cid)) return;
    if (cid==0 || (cid!=CTAPHID_BROADCAST && cid>s->last_cid)) {
        error(s,cid,INVALID_CID); return;
    }
    if (cid==CTAPHID_BROADCAST && (!initial || p[4]!=INIT)) {
        error(s,cid,INVALID_CID); return;
    }
    if (initial) {
        uint16_t n=(uint16_t)(((uint16_t)p[5]<<8)|p[6]);
        if (p[4]==INIT) {
            if (n!=8) { error(s,cid,INVALID_LEN); return; }
            if ((s->receiving || s->transmitting || s->executing) && cid!=s->active_cid) {
                error(s,cid,BUSY); return;
            }
            abort_transaction(s);
            uint32_t allocated=cid;
            if (cid==CTAPHID_BROADCAST) {
                if (s->last_cid==UINT32_MAX-1) { error(s,cid,0x7f); return; }
                allocated=++s->last_cid;
            }
            memcpy(s->tx,p+7,8); put32(s->tx+8,allocated);
            s->tx[12]=2; s->tx[13]=0; s->tx[14]=1; s->tx[15]=0;
            s->tx[16]=0x0c; /* CBOR, no legacy MSG; no unimplemented WINK. */
            respond(s,cid,INIT,17); return;
        }
        if (s->executing && p[4]==CANCEL && cid==s->active_cid) {
            if (n) { error(s,cid,INVALID_LEN); return; }
            abort_transaction(s); s->tx[0]=0x2d;
            respond(s,cid,CBOR,1); return; /* No reply to CANCEL itself. */
        }
        if ((s->receiving || s->transmitting || s->executing)) {
            /* CANCEL does not cancel incomplete packet assembly or emit a reply.
             * Async user-presence cancellation belongs to the CTAP dispatcher. */
            if (p[4]==CANCEL && cid==s->active_cid && n==0) return;
            error(s,cid,BUSY); return;
        }
        if (p[4]==CANCEL) { if (n) error(s,cid,INVALID_LEN); return; }
        if (p[4]!=PING && p[4]!=CBOR) { error(s,cid,INVALID_CMD); return; }
        if (n>CTAPHID_MAX_MESSAGE || (p[4]==CBOR && n==0)) {
            error(s,cid,INVALID_LEN); return;
        }
        s->active_cid=cid; s->rx_command=p[4]; s->rx_length=n;
        s->rx_used=n<57?n:57; s->rx_sequence=0; s->rx_started=now;
        s->receiving=true; memcpy(s->rx,p+7,s->rx_used);
        if (s->rx_used==s->rx_length) complete(s,now);
    } else {
        if (!s->receiving) return; /* Spurious continuation ignored. */
        if (cid!=s->active_cid) { error(s,cid,BUSY); return; }
        if (p[4]!=s->rx_sequence) {
            abort_transaction(s); error(s,cid,INVALID_SEQ); return;
        }
        s->rx_sequence++;
        size_t take=s->rx_length-s->rx_used; if (take>59) take=59;
        memcpy(s->rx+s->rx_used,p+5,take); s->rx_used+=(uint16_t)take;
        if (s->rx_used==s->rx_length) complete(s,now);
    }
}
bool ctaphid_peek(ctaphid_state *s, uint8_t p[64], uint32_t *ticket) {
    if (!s->pending_ticket) {
        memset(s->pending,0,64);
        s->pending_keepalive=false;
        if (s->error_count) {
            ctaphid_error *e=&s->errors[s->error_head];
            put32(s->pending,e->cid); s->pending[4]=ERROR;
            s->pending[6]=1; s->pending[7]=e->code;
            s->pending_error=true; s->pending_bytes=0;
        } else if (s->transmitting) {
            put32(s->pending,s->active_cid);
            size_t offset, take=s->tx_length-s->tx_used;
            if (!s->tx_used && s->tx_sequence==0) {
                s->pending[4]=s->tx_command;
                s->pending[5]=(uint8_t)(s->tx_length>>8); s->pending[6]=(uint8_t)s->tx_length;
                offset=7; if (take>57) take=57;
            } else {
                s->pending[4]=s->tx_sequence; offset=5; if (take>59) take=59;
            }
            memcpy(s->pending+offset,s->tx+s->tx_used,take);
            s->pending_error=false; s->pending_bytes=(uint16_t)take;
        } else if (s->executing && s->keepalive_ready) {
            put32(s->pending,s->active_cid); s->pending[4]=KEEPALIVE;
            s->pending[6]=1; s->pending[7]=s->keepalive_status;
            s->pending_error=false; s->pending_keepalive=true; s->pending_bytes=0;
            s->keepalive_ready=false;
        } else return false;
        s->ticket_counter++; if (!s->ticket_counter) s->ticket_counter++;
        s->pending_ticket=s->ticket_counter;
    }
    memcpy(p,s->pending,64); *ticket=s->pending_ticket; return true;
}
void ctaphid_ack(ctaphid_state *s, uint32_t ticket) {
    if (!ticket || ticket!=s->pending_ticket) return;
    if (s->pending_error) { s->error_head=(s->error_head+1)%4; s->error_count--; }
    else if (s->pending_keepalive) { /* No final-response progress. */ }
    else {
        bool first=s->tx_used==0;
        s->tx_used+=s->pending_bytes;
        if (!first) s->tx_sequence++;
        if (s->tx_used==s->tx_length) {
            s->transmitting=false; memset(s->tx,0,sizeof(s->tx));
        }
    }
    s->pending_ticket=0;
}
