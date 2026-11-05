/* Operational reconstruction, not original Victoria II source.
 * Target SHA256 62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648.
 * Daily country preparation RVA 0x285aa9..0x285ae4, base 0x00400000.
 * Existing typed, accessible graphs; immutable descriptors/globals during phase;
 * nonnegative aligned vector lengths; no concurrent consumer; ESI=0, DF=0.
 */
#include <stdint.h>
typedef volatile uint32_t Word;
static Word *at(uint32_t address) { return (Word*)(uintptr_t)address; }
static uint32_t field(uint32_t object,uint32_t offset) { return *at(object+offset); }
static void zero_words(uint32_t address,unsigned count) {
    for(unsigned i=0;i<count;++i) at(address)[i]=0;
}

uint32_t phase_c(uint32_t world,int32_t count) {
    uint32_t last=0;
    for(int32_t i=0;i<count;++i) {
        uint32_t country=at(field(world,0xadc))[i];
        uint32_t ring=*at(0x1258738);
        unsigned first_words=22;
#ifdef V2_OMIT_LAST_WORD
        --first_words;
#endif
        zero_words(field(country,(ring+11)*16),first_words);
        zero_words(field(country,(ring+13)*16),20);
        uint32_t begin=field(country,0xa0),end=field(country,0xa4);
        for(uint32_t p=begin;p<end;p+=4) {
            uint32_t market=*at(p),slot=*at(0x12586e4);
            zero_words(market+0x48+slot*8,2);
            uint32_t values=field(market,0x28+slot*16);
            uint32_t limit=field(market,0x2c+slot*16);
            zero_words(values,(limit-values)/4);
        }
        /* Retain the original read-only traversal, including its access order. */
        for(uint32_t node=field(country,0xe44);node;node=field(node,8)) { }
        last=at(field(world,0xadc))[i];
        *at(last+0xe80)=field(last,0xe78);
        *at(last+0xe84)=field(last,0xe7c);
    }
    return last;
}
