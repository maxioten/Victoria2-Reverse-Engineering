#include "p2_layout.h"

.text
.globl _cr_sese_entry, _cr_sese_config

.balign 16
_cr_sese_entry:
    cld
    movl %esp, %eax             /* eax = esp_in (Country_Recalculate stack frame) */
    pushl %ebp
    pushl %ebx
    call .Lcr_pc
.Lcr_pc_ret:
    addl $(_cr_sese_config - .Lcr_pc_ret), %edx
    movl %edx, %esi             /* esi (callee-saved) = &_cr_sese_config */
#ifdef P2_CR_BENCH_RDTSC
    movl %eax, %edi             /* edi (callee-saved) = esp_in */
    lfence
    rdtsc
    pushl %edx                  /* t0_hi */
    pushl %eax                  /* t0_lo */
    pushl %esi                  /* arg2: cfg */
    pushl %edi                  /* arg1: esp_in */
    pushl %ebx                  /* arg0: self */
    call _cr_sese_body
    addl $12, %esp
    lfence
    rdtsc
    popl %ecx                   /* t0_lo */
    popl %edi                   /* t0_hi */
    subl %ecx, %eax
    sbbl %edi, %edx
    movl CFG_CR_BENCH_CB(%esi), %ecx
    testl %ecx, %ecx
    jz .Lcr_bench_done
    pushl CFG_CR_BENCH_CTX(%esi)
    pushl $1                    /* variant_a = 1 */
    pushl %edx
    pushl %eax
    call *%ecx
    addl $16, %esp
.Lcr_bench_done:
#else
    pushl %esi                  /* arg2: cfg */
    pushl %eax                  /* arg1: esp_in */
    pushl %ebx                  /* arg0: self */
    call _cr_sese_body
    addl $12, %esp
#endif
    popl %ebx
    popl %ebp
    cld
    jmp *CFG_CR_EXIT_VA(%esi)

.Lcr_pc:
    movl (%esp), %edx
    ret

.balign 16
_cr_sese_config:
    .space CFG_CR_SIZE, 0
