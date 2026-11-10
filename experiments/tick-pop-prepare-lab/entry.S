.text
.globl _phase_entry
_phase_entry:
    pushfl
    andl $0xfffefeff,(%esp)
    pushal
    cld
    subl $16,%esp
    movl %esp,%eax
    pushl %eax
    pushl 36(%esp)
    call _phase_c
    addl $8,%esp
    movl 0(%esp),%eax
    movl %eax,44(%esp)
    movl 12(%esp),%eax
    movl %eax,16(%esp)
    testl %eax,%eax
    jz .Lempty
    movl %eax,36(%esp)
    movl 4(%esp),%eax
    movl %eax,40(%esp)
    movl 8(%esp),%eax
    movl %eax,20(%esp)
.Lempty:
    andl $0xfffff72a,48(%esp)
    orl $0x44,48(%esp)
    addl $16,%esp
    popal
    popfl
    ret
