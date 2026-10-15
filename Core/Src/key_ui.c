#include "key_ui.h"
#include <string.h>

void key_ui_init(key_ui *ui, uint32_t now) {
    if (!ui) return;
    memset(ui, 0, sizeof(*ui));
    ui->changed_at = now;
    ui->candidate = 255; /* Require a debounced all-released state at startup. */
}
bool key_ui_poll(key_ui *ui, uint32_t now, uint8_t raw) {
    if (!ui) return false;
    raw &= 3;
    if (raw != ui->candidate) { ui->candidate=raw; ui->changed_at=now; }
    bool changed=false;
    if ((uint32_t)(now-ui->changed_at)>=35 && raw!=ui->stable) {
        uint8_t previous=ui->stable;
        ui->stable=raw;
        if (!ui->armed) {
            if (!raw) { ui->armed=true; ui->consumed=false; }
            return false;
        }
        if (raw==3 || (previous && raw && previous!=raw)) {
            ui->armed=false; ui->consumed=true;
            return false;
        }
        if (raw) { ui->pressed_at=now; ui->consumed=false; }
        else if (!ui->consumed) {
            if (previous==1 && !ui->page) {
                ui->selected=(uint8_t)((ui->selected+1)%5); changed=true;
            } else if (previous==2 && ui->page) { ui->page=0; changed=true; }
        }
    }
    /* Initial stable==0 also needs to arm after its debounce window. */
    if (!ui->armed && !raw && !ui->stable &&
        (uint32_t)(now-ui->changed_at)>=35) { ui->armed=true; ui->consumed=false; }
    /* Do not recognize a hold while a release/chord is being debounced. */
    if (ui->armed && raw==1 && ui->stable==1 && !ui->consumed &&
        (uint32_t)(now-ui->pressed_at)>=700) {
        ui->consumed=true;
        if (!ui->page) { ui->page=(uint8_t)(ui->selected+1); changed=true; }
    }
    return changed;
}

/* Original 5x7 uppercase cells, each row stored in the low five bits. */
typedef struct { char c; uint8_t rows[7]; } glyph;
static const glyph font[]={
 {'A',{14,17,17,31,17,17,17}}, {'B',{30,17,17,30,17,17,30}},
 {'C',{14,17,16,16,16,17,14}}, {'D',{30,17,17,17,17,17,30}},
 {'E',{31,16,16,30,16,16,31}}, {'F',{31,16,16,30,16,16,16}},
 {'G',{14,17,16,23,17,17,15}}, {'H',{17,17,17,31,17,17,17}},
 {'I',{31,4,4,4,4,4,31}}, {'J',{7,2,2,2,18,18,12}},
 {'K',{17,18,20,24,20,18,17}}, {'L',{16,16,16,16,16,16,31}},
 {'M',{17,27,21,21,17,17,17}}, {'N',{17,25,25,21,19,19,17}},
 {'O',{14,17,17,17,17,17,14}}, {'P',{30,17,17,30,16,16,16}},
 {'Q',{14,17,17,17,21,18,13}}, {'R',{30,17,17,30,20,18,17}},
 {'S',{15,16,16,14,1,1,30}}, {'T',{31,4,4,4,4,4,4}},
 {'U',{17,17,17,17,17,17,14}}, {'V',{17,17,17,17,17,10,4}},
 {'W',{17,17,17,21,21,21,10}}, {'X',{17,17,10,4,10,17,17}},
 {'Y',{17,17,10,4,4,4,4}}, {'Z',{31,1,2,4,8,16,31}},
 {'0',{14,17,19,21,25,17,14}}, {'1',{4,12,4,4,4,4,14}},
 {'2',{14,17,1,2,4,8,31}}, {'3',{30,1,1,14,1,1,30}},
 {'4',{2,6,10,18,31,2,2}}, {'5',{31,16,16,30,1,1,30}},
 {'6',{14,16,16,30,17,17,14}}, {'7',{31,1,2,4,8,8,8}},
 {'8',{14,17,17,14,17,17,14}}, {'9',{14,17,17,15,1,1,14}},
 {'-',{0,0,0,31,0,0,0}}, {'.',{0,0,0,0,0,6,6}},
 {'/',{1,2,2,4,8,8,16}}, {':',{0,6,6,0,6,6,0}},
 {'>',{16,8,4,2,4,8,16}}, {'?',{14,17,1,2,4,0,4}}
};
#define BG 0x18c3u
#define FG 0xef5cu
#define MUTED 0xad33u
#define ACCENT 0xe50fu
#define SELECTED 0x3144u
static const char *const names[]={"FIDO2", "TOTP", "PASSWORDS", "SETTINGS", "DEVICE"};
static int text(key_ui_rect draw, void *ctx, unsigned x, unsigned y,
                const char *s, unsigned scale, uint16_t color) {
    for (; *s; ++s, x+=6*scale) {
        if (*s==' ') continue;
        const uint8_t *rows=font[sizeof(font)/sizeof(font[0])-1].rows;
        for (unsigned i=0;i<sizeof(font)/sizeof(font[0]);++i)
            if (font[i].c==*s) { rows=font[i].rows; break; }
        for (unsigned r=0;r<7;++r) for (unsigned c=0;c<5;++c)
            if (rows[r] & (16u>>c)) {
                int rc=draw(ctx,(uint16_t)(x+c*scale),(uint16_t)(y+r*scale),
                            (uint16_t)scale,(uint16_t)scale,color);
                if (rc) return rc;
            }
    }
    return 0;
}
int key_ui_render(const key_ui *ui, key_ui_rect draw, void *ctx) {
    if (!ui || !draw || ui->selected>=5 || ui->page>5) return -1;
    int rc;
#define RECT(x,y,w,h,c) do { rc=draw(ctx,x,y,w,h,c); if(rc) return rc; } while(0)
#define TEXT(x,y,s,z,c) do { rc=text(draw,ctx,x,y,s,z,c); if(rc) return rc; } while(0)
    RECT(0,0,240,320,BG);
    TEXT(12,14,"STM32 KEY",2,FG);
    TEXT(12,38,"BASELINE / NO SD",1,ACCENT);
    RECT(12,56,216,1,MUTED);
    if (!ui->page) {
        for (unsigned i=0;i<5;++i) {
            unsigned y=72+i*34;
            if (i==ui->selected) { RECT(8,y-7,224,30,SELECTED); TEXT(12,y,">",2,ACCENT); }
            TEXT(30,y,names[i],2,FG);
        }
    } else {
        TEXT(12,74,names[ui->page-1],2,ACCENT);
        switch (ui->page) {
        case 1:
            TEXT(12,112,"USB DIAGNOSTICS ONLY",1,FG);
            TEXT(12,136,"INIT / PING / GETINFO",1,MUTED);
            TEXT(12,168,"CREDENTIAL BACKEND OFF",1,ACCENT);
            TEXT(12,192,"REGISTRATION NOT READY",1,MUTED);
            break;
        case 2:
            TEXT(12,112,"NO ACCOUNT PROVISIONED",1,FG);
            TEXT(12,144,"RTC NOT INITIALIZED",1,ACCENT);
            TEXT(12,176,"NO LIVE CODES AVAILABLE",1,MUTED);
            TEXT(12,208,"PUBLIC VECTOR TEST ONLY",1,MUTED);
            break;
        case 3:
            TEXT(12,112,"VAULT NOT AVAILABLE",1,FG);
            TEXT(12,144,"NO SD / NO DATA ACCESS",1,MUTED);
            TEXT(12,176,"NO SECRET PROVISIONING",1,MUTED);
            break;
        case 4:
            TEXT(12,112,"NAVIGATION ONLY",1,FG);
            TEXT(12,144,"CAP DRIVER NOT READY",1,ACCENT);
            TEXT(12,176,"AUTH FALLBACK DISABLED",1,MUTED);
            TEXT(12,208,"NO SETTINGS ARE SAVED",1,MUTED);
            break;
        case 5:
            TEXT(12,112,"STM32F103RC / 48K RAM",1,FG);
            TEXT(12,144,"ILI9341 / 240 X 320",1,MUTED);
            TEXT(12,176,"SWD PRESERVED",1,MUTED);
            TEXT(12,208,"SD ACCESS DISABLED",1,MUTED);
            break;
        }
    }
    RECT(12,264,216,1,MUTED);
    TEXT(12,278,"A1 NEXT / HOLD ENTER",1,FG);
    TEXT(12,294,"A2 BACK / NAV ONLY",1,MUTED);
    return 0;
#undef RECT
#undef TEXT
}

int key_ui_render_update(const key_ui *ui, const key_ui *previous,
                         key_ui_rect draw, void *ctx) {
    if (!ui || !previous || !draw || ui->selected>=5 || ui->page>5 ||
        previous->selected>=5 || previous->page>5) return -1;
    if (ui->page!=previous->page) return key_ui_render(ui,draw,ctx);
    if (ui->page || ui->selected==previous->selected) return 0;
    const unsigned rows[]={previous->selected,ui->selected};
    for (unsigned n=0;n<2;++n) {
        unsigned i=rows[n], y=72+i*34;
        bool selected=i==ui->selected;
        int rc=draw(ctx,8,(uint16_t)(y-7),224,30,selected?SELECTED:BG);
        if (rc) return rc;
        if (selected) { rc=text(draw,ctx,12,y,">",2,ACCENT); if(rc) return rc; }
        rc=text(draw,ctx,30,y,names[i],2,FG);
        if (rc) return rc;
    }
    return 0;
}
