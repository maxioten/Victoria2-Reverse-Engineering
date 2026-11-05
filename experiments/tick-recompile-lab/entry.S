/* Experimental fragment ABI bridge: EAX=state, ECX=counter, EDX=output.
 * Enter with a synthetic return address on stack. RET restores the original ESP.
 * Reproduce the original fragment's exit integer registers and arithmetic flags.
 * The C body and bridge contain no floating-point/SIMD instructions.
 */
.text
.globl _phase_entry
_phase_entry:
    pushfl
    /* A debugger's breakpoint step-over may inject TF into the first PUSHFD.
     * TF/RF belong to debugger dispatch and are explicitly outside the phase ABI.
     */
    andl $0xfffefeff,(%esp)
    pushal
    pushl %edx
    pushl %ecx
    pushl %eax
    call _phase_c
    addl $12,%esp
    movl %eax,24(%esp)
    movl 28(%esp),%eax
    movl 2496(%eax),%edx
    movl %edx,20(%esp)
    xorl %eax,%eax
    testl %edx,%edx
    sete %al
    movl %eax,28(%esp)
    movl $624,0(%esp)
    movl $1000,4(%esp)
    popal
    popfl
    cmpl $1000,%esi
    ret
