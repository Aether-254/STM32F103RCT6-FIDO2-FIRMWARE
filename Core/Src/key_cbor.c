#include "key_cbor.h"
#include <string.h>

static bool utf8(const uint8_t *p, size_t n) {
    for (size_t i=0; i<n;) {
        uint8_t b=p[i++];
        if (b<0x80) continue;
        unsigned count; uint32_t code, minimum;
        if (b>=0xc2 && b<=0xdf) { count=1; code=b&31; minimum=0x80; }
        else if (b>=0xe0 && b<=0xef) { count=2; code=b&15; minimum=0x800; }
        else if (b>=0xf0 && b<=0xf4) { count=3; code=b&7; minimum=0x10000; }
        else return false;
        if (n-i<count) return false;
        for (unsigned j=0; j<count; j++) {
            uint8_t next=p[i++]; if ((next&0xc0)!=0x80) return false;
            code=(code<<6)|(next&63);
        }
        if (code<minimum || code>0x10ffff || (code>=0xd800 && code<=0xdfff)) return false;
    }
    return true;
}
static int compare(const key_cbor_item *a, const key_cbor_item *b) {
    if (a->major!=b->major) return a->major<b->major?-1:1;
    if (a->encoded_length!=b->encoded_length) return a->encoded_length<b->encoded_length?-1:1;
    return memcmp(a->encoded,b->encoded,a->encoded_length);
}
static bool read_item(const uint8_t *p, size_t n, unsigned depth, key_cbor_item *out) {
    if (!n) return false;
    uint8_t major=p[0]>>5, ai=p[0]&31;
    if (ai>=28 || major==6) return false; /* No indefinite lengths or tags. */
    size_t header=1; uint64_t value=ai;
    if (ai>=24) {
        unsigned bytes=1u<<(ai-24); header+=bytes;
        if (n<header) return false;
        value=0; for (unsigned i=1; i<header; i++) value=(value<<8)|p[i];
        if (major!=7) {
            uint64_t min=ai==24?24:ai==25?256:ai==26?65536:UINT64_C(4294967296);
            if (value<min) return false;
        } else if (ai==24 && value<32) return false;
    }
    size_t used=header;
    key_cbor_item item={.encoded=p,.major=major,.value=value};
    if (major==2 || major==3) {
        if (value>n-header) return false;
        item.data=p+header; item.data_length=(size_t)value; used+=(size_t)value;
        if (major==3 && !utf8(item.data,item.data_length)) return false;
    } else if (major==4 || major==5) {
        if (depth>=KEY_CBOR_MAX_DEPTH) return false;
        /* Each child takes at least one byte. This bounds counts and work even
         * when a hostile header contains UINT64_MAX or cannot fit size_t. */
        if (value>(n-header)/(major==5?2u:1u)) return false;
        item.data=p+header;
        key_cbor_item previous={0}; bool have_previous=false;
        for (uint64_t i=0; i<value; i++) {
            key_cbor_item child;
            if (!read_item(p+used,n-used,depth+1,&child)) return false;
            used+=child.encoded_length;
            if (major==5) {
                if (child.major==4 || child.major==5) return false;
                if (have_previous && compare(&previous,&child)>=0) return false;
                previous=child; have_previous=true;
                if (!read_item(p+used,n-used,depth+1,&child)) return false;
                used+=child.encoded_length;
            }
        }
        item.data_length=used-header;
    }
    item.encoded_length=used; *out=item; return true;
}
bool key_cbor_parse(const uint8_t *p, size_t n, key_cbor_item *root) {
    if (!root) return false;
    memset(root,0,sizeof(*root));
    key_cbor_item item;
    if (!p || n>KEY_CBOR_MAX_SIZE || !read_item(p,n,0,&item) || item.encoded_length!=n) return false;
    *root=item; return true;
}
static bool map_get(const key_cbor_item *map, uint64_t number, const char *text, key_cbor_item *out) {
    if (!map || !out || map->major!=5) return false;
    size_t used=0;
    for (uint64_t i=0; i<map->value; i++) {
        key_cbor_item key, value;
        if (!read_item(map->data+used,map->data_length-used,0,&key)) return false;
        used+=key.encoded_length;
        if (!read_item(map->data+used,map->data_length-used,0,&value)) return false;
        used+=value.encoded_length;
        if (text ? key_cbor_text_equals(&key,text) : key.major==0 && key.value==number) {
            *out=value; return true;
        }
    }
    return false;
}
bool key_cbor_map_uint(const key_cbor_item *m, uint64_t k, key_cbor_item *v) { return map_get(m,k,NULL,v); }
bool key_cbor_map_text(const key_cbor_item *m, const char *k, key_cbor_item *v) {
    return k && map_get(m,0,k,v);
}
bool key_cbor_array_at(const key_cbor_item *a, size_t index, key_cbor_item *out) {
    if (!a || !out || a->major!=4 || index>=a->value) return false;
    size_t used=0;
    for (size_t i=0; i<=index; i++) {
        key_cbor_item item;
        if (!read_item(a->data+used,a->data_length-used,0,&item)) return false;
        used+=item.encoded_length;
        if (i==index) { *out=item; return true; }
    }
    return false;
}
bool key_cbor_text_equals(const key_cbor_item *item, const char *text) {
    return item && text && item->major==3 && item->data_length==strlen(text) &&
           memcmp(item->data,text,item->data_length)==0;
}
