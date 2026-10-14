#include "ctap_dispatch.h"
#include "ctap_request.h"
#include <string.h>

/* Engineering-only getInfo. Authentication commands fail closed until the
 * crypto, fresh user-presence and persistent-storage backends are implemented.
 * This is NOT a claim of FIDO conformance or a production authenticator. */
size_t ctap_dispatch(const uint8_t *req, size_t n, uint8_t *out, size_t cap) {
    static const uint8_t info[] = {
        0x00, 0xa8,
        0x01, 0x81, 0x68, 'F','I','D','O','_','2','_','0',
        0x03, 0x50, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0x04, 0xa2, 0x62,'r','k',0xf4, 0x62,'u','p',0xf5,
        0x05, 0x19, 0x10, 0x00,
        0x07, 0x10,
        0x08, 0x19, 0x01, 0x00,
        0x09, 0x81, 0x63,'u','s','b',
        0x0a, 0x81, 0xa2, 0x63,'a','l','g',0x26,
                            0x64,'t','y','p','e',0x6a,'p','u','b','l','i','c','-','k','e','y'
    };
    if (!cap || !out) return 0;
    if (!req || !n) { out[0]=0x03; return 1; }
    if (req[0]==0x04) {
        if (n!=1) { out[0]=0x03; return 1; }
        if (cap<sizeof(info)) { out[0]=0x7f; return 1; }
        memcpy(out,info,sizeof(info)); return sizeof(info);
    }
    /* Never silently generate insecure credentials, pretend to check presence,
     * reset persistent state or accept a PIN before the real backends exist. */
    if (req[0]==1 || req[0]==2) {
        ctap_request request;
        out[0]=ctap_request_decode(req,n,&request);
        if (!out[0]) out[0]=0x27; /* Schema success is not authentication. */
    } else out[0]=req[0]==0x07?0x27:0x01;
    return 1;
}
