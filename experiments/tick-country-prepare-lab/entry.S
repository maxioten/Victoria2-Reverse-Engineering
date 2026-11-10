.text
.globl _phase_entry
_phase_entry:
    pushfl
    andl $0xfffefeff,(%esp)
    pushal
    cld
    pushl %edi
    pushl %ebx
    call _phase_c
    addl $8,%esp
    cmpl $0,0(%esp)
    jle .Lempty
    movl %eax,28(%esp)
    movl 0xe78(%eax),%ecx
    movl %ecx,24(%esp)
    movl 0xe7c(%eax),%edx
    movl %edx,20(%esp)
    movl 0(%esp),%eax
    movl %eax,4(%esp)
    movl $0x44,%eax
    jmp .Lflags
.Lempty:
    movl 0(%esp),%eax
    testl %eax,%eax
    pushfl
    popl %eax
    andl $0x8d5,%eax
.Lflags:
    andl $0xfffff72a,32(%esp)
    orl %eax,32(%esp)
    popal
    popfl
    ret
