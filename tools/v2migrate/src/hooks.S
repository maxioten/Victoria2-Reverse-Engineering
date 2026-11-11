/* Transparent stubs for v2migrate.
 * Tick stub: observe once, restore everything, jmp to the original tick.
 * New-site stub: entered as `push 0xAC; call new`. Preserves everything,
 * asks the bump allocator; on fallback (EAX=0) tail-jmps to the original
 * operator new. Plain `ret` afterwards so the caller's `add esp,4`
 * (cdecl) still balances the pushed size, exactly as with the original.
 */
.text
.globl _migrate_tick_entry
_migrate_tick_entry:
    pushal
    pushfl
    movl %esp, %ebx
    subl $16, %esp
    andl $-16, %esp
    call _migrate_note_tick
    addl $16, %esp
    movl %ebx, %esp
    popfl
    popal
    jmp *_migrate_orig_tick

.globl _migrate_new_entry
_migrate_new_entry:
    pushal
    pushfl
    movl %esp, %ebx
    subl $16, %esp
    andl $-16, %esp
    pushl 40(%ebx)             /* size arg above our frame */
    call _migrate_bump_alloc
    addl $16, %esp
    movl %ebx, %esp
    cmpl $0, %eax
    je 1f
    movl %eax, 32(%ebx)        /* saved-EAX slot in pushal block */
    popfl
    popal
    ret                        /* caller cleans the pushed size */
1:
    movl %ebx, %esp
    popfl
    popal
    jmp *_migrate_orig_new
