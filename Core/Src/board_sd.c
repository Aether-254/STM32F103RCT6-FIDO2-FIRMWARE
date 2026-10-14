#include "board_sd.h"
#include "key_sd_readonly.h"
#include "board_keys.h"
#include "fido_usb.h"
#include "stm32f1xx_hal.h"
#include <string.h>

volatile board_sd_diagnostics board_sd_snapshot;
static key_sd_readonly card;
/* Official Embedfire MINI SPI SD map: PA5/6/7, CS PA8. PE0 detect
 * in the old generic BSP is NOT assumed to exist on the 64-pin RC part. */
static int wait_flag(uint32_t mask, bool set) {
    uint32_t start=HAL_GetTick();
    for(uint32_t spins=0;spins<400000u;spins++) {
        if(((SPI1->SR & mask)!=0)==set) return 0;
        if((uint32_t)(HAL_GetTick()-start)>=2u) return -1;
    }
    return -1;
}
static int transfer(void *ctx, uint8_t tx, uint8_t *rx) {
    (void)ctx;
    if(wait_flag(SPI_SR_TXE,true)) return -1;
    *(volatile uint8_t *)&SPI1->DR=tx;
    if(wait_flag(SPI_SR_RXNE,true)) return -1;
    *rx=*(volatile uint8_t *)&SPI1->DR;
    return (SPI1->SR & (SPI_SR_MODF|SPI_SR_OVR)) ? -1 : 0;
}
static void select_card(void *ctx, bool active) {
    (void)ctx;
    /* RXNE normally implies completion; bound final BSY settling too. */
    (void)wait_flag(SPI_SR_BSY,false);
    HAL_GPIO_WritePin(GPIOA,GPIO_PIN_8,active?GPIO_PIN_RESET:GPIO_PIN_SET);
}
static uint32_t tick(void *ctx){(void)ctx;return HAL_GetTick();}
static void poll(void *ctx){(void)ctx;board_keys_poll();fido_usb_poll();}
void board_sd_diagnose(void) {
    GPIO_InitTypeDef g={0};
    memset((void *)&board_sd_snapshot,0,sizeof(board_sd_snapshot));
    board_sd_snapshot.magic=0x53445231u;
    board_sd_snapshot.sequence=1;
    board_sd_snapshot.read_result=KEY_SD_ARGUMENT;
    __HAL_RCC_GPIOA_CLK_ENABLE();__HAL_RCC_SPI1_CLK_ENABLE();
    HAL_GPIO_WritePin(GPIOA,GPIO_PIN_8,GPIO_PIN_SET);
    g.Pin=GPIO_PIN_8;g.Mode=GPIO_MODE_OUTPUT_PP;g.Speed=GPIO_SPEED_FREQ_HIGH;
    HAL_GPIO_Init(GPIOA,&g);
    g.Pin=GPIO_PIN_5|GPIO_PIN_7;g.Mode=GPIO_MODE_AF_PP;HAL_GPIO_Init(GPIOA,&g);
    g.Pin=GPIO_PIN_6;g.Mode=GPIO_MODE_INPUT;g.Pull=GPIO_PULLUP;HAL_GPIO_Init(GPIOA,&g);
    SPI1->CR1=0;SPI1->CR2=0;
    /* 72MHz / 256 = 281.25kHz throughout diagnostics. Mode 0, 8-bit. */
    SPI1->CR1=SPI_CR1_MSTR|SPI_CR1_SSM|SPI_CR1_SSI|SPI_CR1_BR|SPI_CR1_SPE;
    key_sd_bus bus={transfer,select_card,tick,poll};
    int rc=key_sd_readonly_init(&card,&bus,NULL);
    board_sd_snapshot.init_result=rc;
    if(!rc) {
        board_sd_snapshot.sectors=card.sectors;
        memcpy((void *)board_sd_snapshot.csd,card.csd,16);
        memcpy((void *)board_sd_snapshot.cid,card.cid,16);
        uint8_t sector[512];
        rc=key_sd_readonly_read(&card,0,sector);
        board_sd_snapshot.read_result=rc;
        if(!rc) board_sd_snapshot.sector0_signature=((uint32_t)sector[510]<<8)|sector[511];
        /* Do not retain or expose the sector contents in diagnostics. */
        memset(sector,0,sizeof(sector));
    }
    board_sd_snapshot.tick=HAL_GetTick();board_sd_snapshot.sequence=2;
}
