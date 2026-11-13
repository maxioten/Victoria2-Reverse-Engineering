#include "p2_layout.h"

.text
.globl _p2_hook_entry, _p2_pic_nop_entry, _p2_hook_config

.balign 16
_p2_hook_entry:
    pushl $0
    pushal
    pushfl
    cld
    movl %esp, %ebp
    subl $528, %esp
    andl $-16, %esp
    fxsave (%esp)
    call .Lpc
.Lpc_ret:
    addl $(_p2_hook_config - .Lpc_ret), %ebx
    movl %esp, %eax
    pushl %ebx
    pushl %eax
    pushl %ebp
    call _p2_dispatch
    addl $12, %esp
    testl %eax, %eax
    jz .Lfallback_to_original

.Lhandled:
    cmpl $0, CFG_ARG_BYTES(%ebx)
    je .Lhandled_ret0
    cmpl $4, CFG_ARG_BYTES(%ebx)
    je .Lhandled_ret4
    cmpl $8, CFG_ARG_BYTES(%ebx)
    je .Lhandled_ret8
    cmpl $12, CFG_ARG_BYTES(%ebx)
    je .Lhandled_ret12
    /* Fail-safe: unsupported arg_bytes falls back to original_target instead of corrupting stack */
    jmp .Lfallback_to_original

.Lhandled_ret0:
    fxrstor (%esp)
    movl %ebp, %esp
    movl SS_RETADDR(%ebp), %eax
    movl %eax, SS_SLOT(%ebp)
    popfl
    popal
    ret $4

.Lhandled_ret4:
    fxrstor (%esp)
    movl %ebp, %esp
    movl SS_RETADDR(%ebp), %eax
    movl %eax, SS_SLOT(%ebp)
    popfl
    popal
    ret $8

.Lhandled_ret8:
    fxrstor (%esp)
    movl %ebp, %esp
    movl SS_RETADDR(%ebp), %eax
    movl %eax, SS_SLOT(%ebp)
    popfl
    popal
    ret $12

.Lhandled_ret12:
    fxrstor (%esp)
    movl %ebp, %esp
    movl SS_RETADDR(%ebp), %eax
    movl %eax, SS_SLOT(%ebp)
    popfl
    popal
    ret $16

.Lfallback_to_original:
    movl CFG_ORIG_TARGET(%ebx), %eax
    movl %eax, SS_SLOT(%ebp)
    fxrstor (%esp)
    movl %ebp, %esp
    popfl
    popal
    ret

.balign 16
_p2_pic_nop_entry:
    pushl $0
    pushal
    pushfl
    cld
    movl %esp, %ebp
    subl $528, %esp
    andl $-16, %esp
    fxsave (%esp)
    call .Lpc
.Lnop_pc_ret:
    addl $(_p2_hook_config - .Lnop_pc_ret), %ebx
    jmp .Lfallback_to_original

.Lpc:
    movl (%esp), %ebx
    ret

.balign 16
_p2_hook_config:
    .space CFG_SIZE, 0
