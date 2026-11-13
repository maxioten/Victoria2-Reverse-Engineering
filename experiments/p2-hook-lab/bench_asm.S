.text
.globl _dummy_target_ret4, _dummy_target_ret4@4
.globl _bench_run_direct_batch, _bench_callsite_direct
.globl _bench_run_vtable_batch
.globl _bench_run_threaded_batch, _bench_callsite_threaded

.balign 16
_dummy_target_ret4:
_dummy_target_ret4@4:
    movl 4(%esp), %eax
    ret $4

/* uint32_t __cdecl bench_run_direct_batch(uint32_t count, uint32_t seed) */
.balign 16
_bench_run_direct_batch:
    pushl %ebp
    movl %esp, %ebp
    pushl %ebx
    movl 8(%ebp), %ebx
    movl 12(%ebp), %eax
    testl %ebx, %ebx
    jz 2f
1:
    pushl %eax
    movl %eax, %ecx
_bench_callsite_direct:
    call _dummy_target_ret4
    addl $1, %eax
    decl %ebx
    jnz 1b
2:
    popl %ebx
    popl %ebp
    ret

/* uint32_t __cdecl bench_run_vtable_batch(uint32_t count, void *obj_with_vtbl, uint32_t seed) */
.balign 16
_bench_run_vtable_batch:
    pushl %ebp
    movl %esp, %ebp
    pushl %ebx
    pushl %esi
    movl 8(%ebp), %ebx
    movl 12(%ebp), %esi
    movl 16(%ebp), %eax
    testl %ebx, %ebx
    jz 2f
1:
    pushl %eax
    movl %esi, %ecx
    movl (%esi), %edx
    call *(%edx)
    addl $1, %eax
    decl %ebx
    jnz 1b
2:
    popl %esi
    popl %ebx
    popl %ebp
    ret

/* uint32_t __cdecl bench_run_threaded_batch(uint32_t count, uint32_t seed) */
.balign 16
_bench_run_threaded_batch:
    pushl %ebp
    movl %esp, %ebp
    pushl %ebx
    movl 8(%ebp), %ebx
    movl 12(%ebp), %eax
    testl %ebx, %ebx
    jz 2f
1:
    pushl %eax
    movl %eax, %ecx
_bench_callsite_threaded:
    call _dummy_target_ret4
    addl $1, %eax
    decl %ebx
    jnz 1b
2:
    popl %ebx
    popl %ebp
    ret
