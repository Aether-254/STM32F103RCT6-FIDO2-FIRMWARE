#include "key_sd_readonly.h"
#include <limits.h>
#include <string.h>

#define SD_BUDGET_MS 1500u
#define SD_MAX_EXCHANGES 200000u

int key_sd_csd_sectors(const uint8_t c[16], bool block, uint64_t *out) {
    if (!out) return KEY_SD_ARGUMENT;
    *out = 0;
    if (!c || !(c[15] & 1u)) return KEY_SD_PROTOCOL;
    unsigned version = c[0] >> 6;
    if (version == 1 && block && (c[5] & 15u) == 9u) {
        uint32_t size = ((uint32_t)(c[7] & 63u) << 16) | ((uint32_t)c[8] << 8) | c[9];
        *out = ((uint64_t)size + 1u) * 1024u;
    } else if (version == 0 && !block) {
        unsigned length = c[5] & 15u;
        if (length < 9u || length > 11u) return KEY_SD_PROTOCOL;
        uint32_t size = ((uint32_t)(c[6] & 3u) << 10) | ((uint32_t)c[7] << 2) | (c[8] >> 6);
        unsigned mult = ((c[9] & 3u) << 1) | (c[10] >> 7);
        *out = ((uint64_t)size + 1u) << (mult + 2u + length - 9u);
        /* SDSC byte addresses must fit the 32-bit command argument. */
        if (*out > (UINT64_C(1) << 23)) { *out = 0; return KEY_SD_PROTOCOL; }
    } else return KEY_SD_PROTOCOL;
    return KEY_SD_OK;
}

static int exchange(key_sd_readonly *s, uint8_t tx, uint8_t *rx) {
    if ((int32_t)(s->bus.tick(s->context) - s->deadline) >= 0 ||
        ++s->exchanges > SD_MAX_EXCHANGES) return KEY_SD_TIMEOUT;
    if ((s->exchanges & 31u) == 0 && s->bus.poll) s->bus.poll(s->context);
    return s->bus.transfer(s->context, tx, rx) == 0 ? KEY_SD_OK : KEY_SD_IO;
}
static void release(key_sd_readonly *s) {
    uint8_t ignored;
    s->bus.select(s->context, false);
    /* Clock after deselect, even on an error; adapter must remain bounded. */
    (void)s->bus.transfer(s->context, 0xff, &ignored);
}
static uint8_t crc7(const uint8_t *p, unsigned n) {
    uint8_t crc=0;
    for (unsigned i=0;i<n;i++) {
        uint8_t b=p[i];
        for (unsigned j=0;j<8;j++) {
            crc <<= 1;
            if ((b ^ crc) & 0x80) crc ^= 9;
            b <<= 1;
        }
    }
    return (uint8_t)((crc << 1) | 1);
}
static uint16_t crc16(const uint8_t *p, unsigned n) {
    uint16_t crc=0;
    for (unsigned i=0;i<n;i++) {
        crc ^= (uint16_t)p[i] << 8;
        for (unsigned j=0;j<8;j++) crc=(uint16_t)((crc << 1) ^ ((crc & 0x8000) ? 0x1021 : 0));
    }
    return crc;
}
static int command(key_sd_readonly *s, unsigned cmd, uint32_t arg, uint8_t *r1) {
    uint8_t packet[6]={(uint8_t)(0x40u|cmd),(uint8_t)(arg>>24),
        (uint8_t)(arg>>16),(uint8_t)(arg>>8),(uint8_t)arg,0};
    packet[5]=crc7(packet,5);
    release(s);
    s->bus.select(s->context,true);
    uint8_t b=0;
    int rc;
    /* Never issue a command while the card drives busy. */
    do { rc=exchange(s,0xff,&b); if(rc) return rc; } while(b!=0xff);
    for(unsigned i=0;i<6;i++) { rc=exchange(s,packet[i],&b); if(rc) return rc; }
    for(unsigned i=0;i<8;i++) {
        rc=exchange(s,0xff,&b); if(rc) return rc;
        if(!(b&0x80)) { *r1=b; return KEY_SD_OK; }
    }
    return KEY_SD_PROTOCOL;
}
static int payload(key_sd_readonly *s, uint8_t *out, unsigned n) {
    uint8_t b=0, hi, lo;
    int rc;
    do {
        rc=exchange(s,0xff,&b); if(rc) return rc;
        if(b!=0xff && b!=0xfe) return KEY_SD_PROTOCOL;
    } while(b!=0xfe);
    for(unsigned i=0;i<n;i++) { rc=exchange(s,0xff,out+i); if(rc) return rc; }
    rc=exchange(s,0xff,&hi); if(rc) return rc;
    rc=exchange(s,0xff,&lo); if(rc) return rc;
    return crc16(out,n)==(((uint16_t)hi<<8)|lo) ? KEY_SD_OK : KEY_SD_CRC;
}
static int reg_read(key_sd_readonly *s, unsigned cmd, uint8_t out[16]) {
    uint8_t r1;
    int rc=command(s,cmd,0,&r1);
    if(rc) return rc;
    if(r1) return KEY_SD_PROTOCOL;
    return payload(s,out,16);
}
int key_sd_readonly_init(key_sd_readonly *s, const key_sd_bus *bus, void *ctx) {
    if(!s || !bus || !bus->transfer || !bus->select || !bus->tick) return KEY_SD_ARGUMENT;
    memset(s,0,sizeof(*s)); s->bus=*bus; s->context=ctx;
    s->deadline=bus->tick(ctx)+SD_BUDGET_MS;
    bus->select(ctx,false);
    uint8_t r1=0,b=0,reply[4]; int rc=KEY_SD_OK;
    bool v2=false;
    for(unsigned i=0;i<10;i++) { rc=exchange(s,0xff,&b); if(rc) goto done; }
    rc=command(s,0,0,&r1); if(rc) goto done;
    if(r1!=1) {rc=KEY_SD_PROTOCOL;goto done;}
    rc=command(s,8,0x1aa,&r1); if(rc) goto done;
    if(r1==1) {
        for(unsigned i=0;i<4;i++){rc=exchange(s,0xff,reply+i);if(rc)goto done;}
        if(reply[0] || reply[1] || reply[2]!=1 || reply[3]!=0xaa){rc=KEY_SD_PROTOCOL;goto done;}
        v2=true;
    } else if(r1!=5) {rc=KEY_SD_PROTOCOL;goto done;}
    do {
        rc=command(s,55,0,&r1);if(rc)goto done;
        if(r1>1){rc=KEY_SD_PROTOCOL;goto done;}
        rc=command(s,41,v2?0x40000000u:0,&r1);if(rc)goto done;
        if(r1>1){rc=KEY_SD_PROTOCOL;goto done;}
    } while(r1==1);
    rc=command(s,58,0,&r1);if(rc)goto done;
    if(r1){rc=KEY_SD_PROTOCOL;goto done;}
    for(unsigned i=0;i<4;i++){rc=exchange(s,0xff,reply+i);if(rc)goto done;}
    if(!(reply[0]&0x80) || !(reply[1]&0x30)){rc=KEY_SD_PROTOCOL;goto done;}
    s->block_addressed=(reply[0]&0x40)!=0;
    if(s->block_addressed && !v2){rc=KEY_SD_PROTOCOL;goto done;}
    if(!s->block_addressed) {
        rc=command(s,16,512,&r1);if(rc)goto done;
        if(r1){rc=KEY_SD_PROTOCOL;goto done;}
    }
    rc=reg_read(s,9,s->csd);if(rc)goto done;
    rc=key_sd_csd_sectors(s->csd,s->block_addressed,&s->sectors);if(rc)goto done;
    rc=reg_read(s,10,s->cid);if(rc)goto done;
    s->ready=true;
done:
    release(s);
    if(rc){s->ready=false;s->sectors=0;memset(s->csd,0,16);memset(s->cid,0,16);}
    return rc;
}
int key_sd_readonly_read(key_sd_readonly *s, uint64_t lba, uint8_t out[512]) {
    if(!out) return KEY_SD_ARGUMENT;
    memset(out,0,512);
    if(!s || !s->ready || lba>=s->sectors || lba>UINT32_MAX ||
       (!s->block_addressed && lba>UINT32_MAX/512u)) return KEY_SD_ARGUMENT;
    s->deadline=s->bus.tick(s->context)+SD_BUDGET_MS;s->exchanges=0;
    uint8_t r1;
    int rc=command(s,17,(uint32_t)(s->block_addressed?lba:lba*512u),&r1);
    if(!rc) rc=r1?KEY_SD_PROTOCOL:payload(s,out,512);
    release(s);
    if(rc){memset(out,0,512);s->ready=false;}
    return rc;
}
