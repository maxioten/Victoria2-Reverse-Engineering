/* Linux i386 entry/IO only; arithmetic bodies below are unchanged original x86 bytes.
 * Windows APIs are not used by these two isolated helpers. */
.include "expected_counts.inc"
.section .text
.global _start
_start:
    mov $fixtures, %esi
    mov $fixtures_end, %ebp
    xor %edi, %edi
    xor %ebx, %ebx
next_fixture:
    cmp %ebp, %esi
    je finished
    push 12(%esi)
    push 8(%esi)
    push 4(%esi)
    push 0(%esi)
    call original_multiply
    cmp 24(%esi), %eax
    jne failed
    cmp 28(%esi), %edx
    jne failed
    cmpl $0, 32(%esi)
    je advance
    push 12(%esi)
    push 8(%esi)
    push 4(%esi)
    push 0(%esi)
    call original_divide
    cmp 16(%esi), %eax
    jne failed
    cmp 20(%esi), %edx
    jne failed
    inc %ebx
advance:
    add $36, %esi
    inc %edi
    jmp next_fixture
finished:
    cmp $EXPECTED_RECORDS, %edi
    jne failed
    cmp $EXPECTED_DIVISIONS, %ebx
    jne failed
    mov $4, %eax
    mov $1, %ebx
    mov $success, %ecx
    mov $success_end-success, %edx
    int $0x80
    mov $1, %eax
    xor %ebx, %ebx
    int $0x80
failed:
    mov $4, %eax
    mov $2, %ebx
    mov $failure, %ecx
    mov $failure_end-failure, %edx
    int $0x80
    mov $1, %eax
    mov $1, %ebx
    int $0x80
.balign 16
original_divide:
.incbin "original_divide.bin"
.balign 16
original_multiply:
.incbin "original_multiply.bin"
.section .rodata
fixtures:
.incbin "fixtures.bin"
fixtures_end:
success:
.ascii "PASS: ELF32 original arithmetic helpers\n"
success_end:
failure:
.ascii "FAIL: ELF32 arithmetic fixture mismatch\n"
failure_end:
.section .note.GNU-stack,"",@progbits
