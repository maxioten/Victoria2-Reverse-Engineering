/* Independently reconstructed whole phase, preferred VA 0x685ae4..0x685b22.
 * The names describe inferred roles. Offset-level effects are the contract.
 * Preconditions: aligned, nonnegative vectors; valid finite linked lists;
 * descriptors, links and global value do not alias reset destinations; DF=0.
 */
#include <stdint.h>
typedef uint32_t U;
typedef struct {U eax,ecx,esi,count;} Result;
static U read32(U a) {return *(volatile const U *)(uintptr_t)a;}
static void write32(U a,U v) {*(volatile U *)(uintptr_t)a=v;}

void phase_c(U world,Result *out) {
    U begin=read32(world+0xacc),end=read32(world+0xad0);
    U count=(end-begin)/4;
    out->count=count;
    out->eax=0;
    for(U i=0;i<count;i++) {
        U province=read32(begin+i*4);
        U groups=read32(province+0x194),limit=read32(province+0x198);
        U n=(limit-groups)/16;
        U c=begin,a=limit-groups;
        for(U j=0;j<n;j++) {
            c=groups;
            U pop=read32(groups+j*16);
            while(pop) {
                for(U k=0;k<9;k++) write32(pop+0x158+k*4,0);
                /* Original rereads both global words for every pair. */
                write32(pop+0x218,read32(0x131b890));
                write32(pop+0x21c,read32(0x131b894));
                for(U k=0;k<8;k++) {
                    c=read32(0x131b890);
                    write32(pop+0x1d8+k*8,c);
#ifndef V2_OMIT_LAST_WORD
                    write32(pop+0x1dc+k*8,read32(0x131b894));
#else
                    if(k!=7) write32(pop+0x1dc+k*8,read32(0x131b894));
#endif
                }
                pop=read32(pop+0x27c);
            }
            a=0;
        }
        out->eax=a;out->ecx=c;out->esi=province;
    }
}
