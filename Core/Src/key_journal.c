#include "key_journal.h"
#include <string.h>

static void wipe(void *p, size_t n) {
    volatile uint8_t *b = p;
    while (n--) *b++ = 0;
}
static int filled(const uint8_t *p, size_t n, uint8_t expected) {
    uint8_t difference = 0;
    while (n--) difference |= *p++ ^ expected;
    return difference == 0;
}
static void put64(uint8_t *p, uint64_t v) {
    for (unsigned i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (56-8*i));
}
static uint64_t get64(const uint8_t *p) {
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}
static int same(const key_journal_state *a, const key_journal_state *b) {
    return a->serial == b->serial && a->nonce == b->nonce && a->sign_count == b->sign_count;
}
static int increasing(const key_journal_state *old, const key_journal_state *new) {
    return new->serial > old->serial && new->nonce >= old->nonce &&
        new->sign_count >= old->sign_count &&
        (new->nonce > old->nonce || new->sign_count > old->sign_count);
}
static int setup(key_journal *j, const key_journal_io *io, void *context,
                 const uint8_t *root, const uint8_t *device) {
    static const uint8_t domain[] = "stm32-fido2/high-water-journal/v2";
    if (!j) return KEY_JOURNAL_BAD_INPUT;
    wipe(j, sizeof(*j));
    if (!io || !io->read || !io->program || !io->erase || !root || !device ||
        filled(root, 32, 0)) return KEY_JOURNAL_BAD_INPUT;
    if (key_crypto_hkdf(root, device, 12, domain, sizeof(domain)-1, j->key))
        return KEY_JOURNAL_IO_FAILED;
    j->io = io; j->context = context;
    return 0;
}
/* Authenticated prepared state burns allocations even without final marker.
 * A55A one-bits must survive a torn FFFF->A55A halfword program. */
static int decode(key_journal *j, const uint8_t *entry, key_journal_state *s) {
    uint16_t marker = ((uint16_t)entry[78] << 8) | entry[79];
    uint8_t mac[32];
    if ((marker & 0xA55Au) != 0xA55Au) return KEY_JOURNAL_CORRUPT;
    if (key_crypto_hmac(j->key, entry, 32, mac)) return KEY_JOURNAL_IO_FAILED;
    uint8_t difference = 0;
    for (unsigned i = 0; i < 32; ++i) difference |= mac[i] ^ entry[32+i];
    wipe(mac, sizeof(mac));
    int canonical = !memcmp(entry, "F2JW", 4) && entry[4] == 2 &&
        filled(entry+5, 3, 0) && filled(entry+28, 4, 0) &&
        (marker != 0xA55Au || filled(entry+64, 14, 0));
    if (difference || !canonical) return marker == 0xA55Au ? KEY_JOURNAL_CORRUPT : 0;
    s->serial = get64(entry+8); s->nonce = get64(entry+16);
    s->sign_count = (uint32_t)entry[24] << 24 | (uint32_t)entry[25] << 16 |
                    (uint32_t)entry[26] << 8 | entry[27];
    if (!s->serial || (s->serial == 1 && (s->nonce || s->sign_count))) return KEY_JOURNAL_CORRUPT;
    return 1;
}
int key_journal_recover(key_journal *j, const key_journal_io *io, void *context,
                        const uint8_t root[32], const uint8_t device[12]) {
    int rc = setup(j, io, context, root, device);
    if (rc) return rc;
    uint8_t entry[80];
    bool dirty = false;
    for (unsigned page = 0; page < 2; ++page) {
        j->healthy[page] = true;
        key_journal_state previous = {0};
        for (unsigned slot = 0; slot < KEY_JOURNAL_SLOTS; ++slot) {
            if (io->read(context, page*2048u + slot*80u, entry, 80)) { rc = KEY_JOURNAL_IO_FAILED; goto done; }
            if (filled(entry, 80, 0xFF)) continue;
            dirty = true; j->next_slot[page] = slot+1;
            key_journal_state state;
            rc = decode(j, entry, &state);
            if (rc == KEY_JOURNAL_IO_FAILED) goto done;
            if (rc < 0) { j->healthy[page] = false; continue; }
            if (!rc) continue;
            /* Identical checkpoint duplicates are legitimate mirror repair.
             * Divergent same serial and decreasing histories are not. */
            if (previous.serial && !same(&previous, &state) && !increasing(&previous, &state)) {
                rc = KEY_JOURNAL_CORRUPT; goto done;
            }
            previous = state;
            if (state.serial > j->page_state[page].serial) j->page_state[page] = state;
            else if (state.serial == j->page_state[page].serial && !same(&state, &j->page_state[page])) {
                rc = KEY_JOURNAL_CORRUPT; goto done;
            }
        }
        if (io->read(context, page*2048u + 2000u, entry, 48)) { rc = KEY_JOURNAL_IO_FAILED; goto done; }
        if (!filled(entry, 48, 0xFF)) { dirty = true; j->healthy[page] = false; }
    }
    if (!j->page_state[0].serial && !j->page_state[1].serial) {
        rc = dirty ? KEY_JOURNAL_CORRUPT : KEY_JOURNAL_UNPROVISIONED; goto done;
    }
    if ((!j->healthy[0] || !j->page_state[0].serial) &&
        (!j->healthy[1] || !j->page_state[1].serial)) { rc = KEY_JOURNAL_CORRUPT; goto done; }
    unsigned newest = j->page_state[1].serial > j->page_state[0].serial ? 1u : 0u;
    unsigned older = 1u-newest;
    if (j->page_state[older].serial && !same(&j->page_state[older], &j->page_state[newest]) &&
        !increasing(&j->page_state[older], &j->page_state[newest])) { rc = KEY_JOURNAL_CORRUPT; goto done; }
    j->state = j->page_state[newest];
    j->ready = true; rc = 0;
done:
    wipe(entry, sizeof(entry));
    if (rc && rc != KEY_JOURNAL_UNPROVISIONED) key_journal_dispose(j);
    return rc;
}
static int append(key_journal *j, unsigned page, const key_journal_state *s) {
    uint8_t entry[80] = {0}, check[80];
    int rc = KEY_JOURNAL_IO_FAILED;
    memcpy(entry, "F2JW", 4); entry[4] = 2;
    put64(entry+8, s->serial); put64(entry+16, s->nonce);
    entry[24] = (uint8_t)(s->sign_count >> 24); entry[25] = (uint8_t)(s->sign_count >> 16);
    entry[26] = (uint8_t)(s->sign_count >> 8); entry[27] = (uint8_t)s->sign_count;
    entry[78] = 0xA5; entry[79] = 0x5A;
    if (key_crypto_hmac(j->key, entry, 32, entry+32)) goto done;
    size_t offset = page*2048u + j->next_slot[page]*80u;
    if (j->next_slot[page] >= KEY_JOURNAL_SLOTS ||
        j->io->read(j->context, offset, check, 80) || !filled(check, 80, 0xFF)) goto done;
    if (j->io->program(j->context, offset, entry, 78)) goto done;
    if (j->io->read(j->context, offset, check, 80) ||
        memcmp(check, entry, 78) || !filled(check+78, 2, 0xFF)) goto done;
    if (j->io->program(j->context, offset+78, entry+78, 2)) goto done;
    if (j->io->read(j->context, offset, check, 80) || memcmp(check, entry, 80)) goto done;
    j->page_state[page] = *s; ++j->next_slot[page]; rc = 0;
done:
    wipe(entry, sizeof(entry)); wipe(check, sizeof(check));
    if (rc) j->ready = false;
    return rc;
}
static int erase_checked(key_journal *j, unsigned page) {
    uint8_t check[80];
    int rc = KEY_JOURNAL_IO_FAILED;
    if (j->io->erase(j->context, page)) goto done;
    for (size_t offset = 0; offset < 2048u; offset += 80u) {
        size_t length = 2048u-offset < 80u ? 2048u-offset : 80u;
        if (j->io->read(j->context, page*2048u+offset, check, length) || !filled(check, length, 0xFF)) goto done;
    }
    memset(&j->page_state[page], 0, sizeof(j->page_state[page]));
    j->next_slot[page] = 0; j->healthy[page] = true; rc = 0;
done:
    wipe(check, sizeof(check));
    if (rc) j->ready = false;
    return rc;
}
/* Erasing page is allowed ONLY while the other page owns the state to retain. */
static int store(key_journal *j, unsigned page, const key_journal_state *state,
                 const key_journal_state *retain) {
    if (!j->healthy[page] || j->next_slot[page] == KEY_JOURNAL_SLOTS) {
        if (!same(&j->page_state[1u-page], retain)) { j->ready = false; return KEY_JOURNAL_CORRUPT; }
        int rc = erase_checked(j, page);
        if (rc) return rc;
    }
    return append(j, page, state);
}
/* Repair lagging side first, leaving highest-state owner untouched. */
static int synchronize(key_journal *j) {
    unsigned owner = same(&j->page_state[0], &j->state) ? 0u : 1u;
    unsigned other = 1u-owner;
    if (!same(&j->page_state[other], &j->state) || !j->healthy[other]) {
        int rc = store(j, other, &j->state, &j->state);
        if (rc) return rc;
    }
    if (!j->healthy[owner]) return store(j, owner, &j->state, &j->state);
    return 0;
}
int key_journal_provision(key_journal *j, const key_journal_io *io, void *context,
                          const uint8_t root[32], const uint8_t device[12]) {
    int rc = key_journal_recover(j, io, context, root, device);
    if (rc != KEY_JOURNAL_UNPROVISIONED) {
        if (!rc) key_journal_dispose(j);
        return rc ? rc : KEY_JOURNAL_BAD_INPUT;
    }
    key_journal_state genesis = {.serial = 1};
    rc = append(j, 0, &genesis);
    if (!rc) rc = append(j, 1, &genesis);
    if (!rc) { j->state = genesis; j->ready = true; }
    return rc;
}
int key_journal_reserve(key_journal *j, uint64_t nonce_amount, uint32_t sign_amount,
                        uint64_t *nonce_first, uint32_t *sign_first) {
    if (nonce_first) *nonce_first = 0;
    if (sign_first) *sign_first = 0;
    if (!j || !j->ready || !nonce_first || !sign_first || (!nonce_amount && !sign_amount)) return KEY_JOURNAL_BAD_INPUT;
    if (j->state.serial == UINT64_MAX || nonce_amount > UINT64_MAX-j->state.nonce ||
        sign_amount > UINT32_MAX-j->state.sign_count) return KEY_JOURNAL_EXHAUSTED;
    int rc = synchronize(j);
    if (rc) return rc;
    key_journal_state next = {j->state.serial+1, j->state.nonce+nonce_amount,
                              j->state.sign_count+sign_amount};
    uint64_t nf = nonce_amount ? j->state.nonce+1 : 0;
    uint32_t sf = sign_amount ? j->state.sign_count+1 : 0;
    rc = store(j, 0, &next, &j->state);
    if (!rc) rc = store(j, 1, &next, &next);
    if (!rc) { j->state = next; *nonce_first = nf; *sign_first = sf; }
    return rc;
}
void key_journal_dispose(key_journal *j) { if (j) wipe(j, sizeof(*j)); }
bool key_journal_matches(const key_journal *j, const uint8_t root[32], const uint8_t device[12]) {
    static const uint8_t domain[] = "stm32-fido2/high-water-journal/v2";
    uint8_t key[32], difference = 0;
    if (!j || !j->ready || !root || !device || filled(root, 32, 0)) return false;
    if (key_crypto_hkdf(root, device, 12, domain, sizeof(domain)-1, key)) {
        wipe(key, sizeof(key)); return false;
    }
    for (unsigned i = 0; i < 32; ++i) difference |= key[i] ^ j->key[i];
    wipe(key, sizeof(key));
    return difference == 0;
}
