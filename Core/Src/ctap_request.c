#include "ctap_request.h"
#include <string.h>
enum { INVALID_PARAMETER=2, UNEXPECTED_TYPE=0x11, INVALID_CBOR=0x12,
       MISSING=0x14, LIMIT=0x15, UNSUPPORTED_ALGORITHM=0x26 };

static uint8_t required(const key_cbor_item *root, unsigned key, uint8_t major, key_cbor_item *value) {
    if (!key_cbor_map_uint(root,key,value)) return MISSING;
    return value->major==major?0:UNEXPECTED_TYPE;
}
static uint8_t bool_option(const key_cbor_item *map, const char *name, bool *value, bool *present) {
    key_cbor_item item;
    if (!key_cbor_map_text(map,name,&item)) return 0;
    if (item.major!=7 || (item.value!=20 && item.value!=21) || item.encoded_length!=1)
        return UNEXPECTED_TYPE;
    *value=item.value==21; if (present) *present=true; return 0;
}
static uint8_t identifier(const key_cbor_item *item) {
    if (!item->data_length || item->data_length>CTAP_MAX_RP_ID) return INVALID_PARAMETER;
    if (memchr(item->data,0,item->data_length)) return INVALID_PARAMETER;
    return 0;
}
static uint8_t descriptors(const key_cbor_item *array) {
    if (array->major!=4) return UNEXPECTED_TYPE;
    if (array->value>CTAP_MAX_CREDENTIAL_LIST) return LIMIT;
    for (size_t i=0; i<array->value; i++) {
        key_cbor_item d, type, id;
        if (!key_cbor_array_at(array,i,&d) || d.major!=5) return UNEXPECTED_TYPE;
        if (!key_cbor_map_text(&d,"type",&type) || !key_cbor_map_text(&d,"id",&id)) return MISSING;
        if (type.major!=3 || id.major!=2) return UNEXPECTED_TYPE;
        if (!id.data_length || id.data_length>CTAP_MAX_CREDENTIAL_ID) return INVALID_PARAMETER;
        /* Unknown credential types are well-formed and must be ignored by the
         * selection layer, never treated as recognized credentials. */
    }
    return 0;
}
static uint8_t algorithms(const key_cbor_item *array) {
    bool supported=false;
    if (!array->value) return INVALID_PARAMETER;
    if (array->value>64) return LIMIT;
    for (size_t i=0; i<array->value; i++) {
        key_cbor_item p, type, alg;
        if (!key_cbor_array_at(array,i,&p) || p.major!=5) return UNEXPECTED_TYPE;
        if (!key_cbor_map_text(&p,"type",&type) || !key_cbor_map_text(&p,"alg",&alg)) return MISSING;
        if (type.major!=3 || (alg.major!=0 && alg.major!=1)) return UNEXPECTED_TYPE;
        if (key_cbor_text_equals(&type,"public-key") && alg.major==1 && alg.value==6) supported=true;
    }
    return supported?0:UNSUPPORTED_ALGORITHM;
}
static uint8_t decode(const uint8_t *p, size_t n, ctap_request *out) {
    if (!p || n<2 || n>KEY_CBOR_MAX_SIZE) return INVALID_CBOR;
    if (p[0]!=1 && p[0]!=2) return 1;
    key_cbor_item root, rp, cdh, options, item;
    if (!key_cbor_parse(p+1,n-1,&root)) return INVALID_CBOR;
    if (root.major!=5) return UNEXPECTED_TYPE;
    uint8_t rc; bool make=p[0]==1;
    if ((rc=required(&root,make?1:2,2,&cdh))) return rc;
    if (cdh.data_length!=32) return INVALID_PARAMETER;
    if ((rc=required(&root,make?2:1,make?5:3,&rp))) return rc;
    if (make) {
        if (!key_cbor_map_text(&rp,"id",&item)) return MISSING;
        if (item.major!=3) return UNEXPECTED_TYPE;
        rp=item;
    }
    if ((rc=identifier(&rp))) return rc;
    out->command=p[0]; out->rp_id=rp.data; out->rp_id_length=rp.data_length;
    out->client_data_hash=cdh.data; out->up=true;
    if (make) {
        key_cbor_item user, user_id, params;
        if ((rc=required(&root,3,5,&user))) return rc;
        if (!key_cbor_map_text(&user,"id",&user_id)) return MISSING;
        if (user_id.major!=2) return UNEXPECTED_TYPE;
        if (!user_id.data_length || user_id.data_length>64) return INVALID_PARAMETER;
        out->user_id=user_id.data; out->user_id_length=user_id.data_length;
        if (key_cbor_map_text(&user,"name",&item) && item.major!=3) return UNEXPECTED_TYPE;
        if (key_cbor_map_text(&user,"displayName",&item) && item.major!=3) return UNEXPECTED_TYPE;
        if ((rc=required(&root,4,4,&params)) || (rc=algorithms(&params))) return rc;
    }
    if (key_cbor_map_uint(&root,make?5:3,&item)) {
        if ((rc=descriptors(&item))) return rc;
        out->credentials=item; out->has_credentials=true;
    }
    if (key_cbor_map_uint(&root,make?6:4,&item) && item.major!=5) return UNEXPECTED_TYPE;
    if (key_cbor_map_uint(&root,make?7:5,&options)) {
        if (options.major!=5) return UNEXPECTED_TYPE;
        if ((rc=bool_option(&options,"rk",&out->rk,NULL)) ||
            (rc=bool_option(&options,"uv",&out->uv,NULL)) ||
            (rc=bool_option(&options,"up",&out->up,&out->has_up))) return rc;
    }
    if (key_cbor_map_uint(&root,make?8:6,&item) && item.major!=2) return UNEXPECTED_TYPE;
    if (key_cbor_map_uint(&root,make?9:7,&item) && item.major!=0) return UNEXPECTED_TYPE;
    return 0;
}
uint8_t ctap_request_decode(const uint8_t *p, size_t n, ctap_request *out) {
    if (!out) return INVALID_PARAMETER;
    memset(out,0,sizeof(*out));
    uint8_t rc=decode(p,n,out);
    if (rc) memset(out,0,sizeof(*out));
    return rc;
}
