/* Stubs transparentes: registran, restauran TODO y saltan al original.
 * No alteran el valor de retorno ni la pila: jmp al original con el mismo estado.
 * Layout tras pushal(32) + pushfl(4): ebx = esp; 36(ebx) = direccion de retorno;
 * 40(ebx) = primer argumento de pila del llamador.
 */
.text
.globl _probe_decision_entry
_probe_decision_entry:
    pushal
    pushfl
    movl %esp, %ebx
    subl $16, %esp
    andl $-16, %esp
    pushl %ecx              /* this en ECX (thiscall) */
    call _probe_note_decision
    addl $16, %esp
    movl %ebx, %esp
    popfl
    popal
    jmp *_probe_orig_decision

.globl _probe_820df0_entry
_probe_820df0_entry:
    pushal
    pushfl
    movl %esp, %ebx
    subl $16, %esp
    andl $-16, %esp
    pushl 40(%ebx)
    call _probe_note_820df0
    addl $16, %esp
    movl %ebx, %esp
    popfl
    popal
    jmp *_probe_orig_820df0

.globl _probe_81e280_entry
_probe_81e280_entry:
    pushal
    pushfl
    movl %esp, %ebx
    subl $16, %esp
    andl $-16, %esp
    pushl 40(%ebx)
    call _probe_note_81e280
    addl $16, %esp
    movl %ebx, %esp
    popfl
    popal
    jmp *_probe_orig_81e280

.globl _probe_81e5b0_entry
_probe_81e5b0_entry:
    pushal
    pushfl
    movl %esp, %ebx
    subl $16, %esp
    andl $-16, %esp
    pushl 40(%ebx)
    call _probe_note_81e5b0
    addl $16, %esp
    movl %ebx, %esp
    popfl
    popal
    jmp *_probe_orig_81e5b0

.globl _probe_throttle_entry
_probe_throttle_entry:
    pushal
    pushfl
    movl %esp, %ebx
    subl $16, %esp
    andl $-16, %esp
    pushl 40(%ebx)
    call _probe_note_throttle
    addl $16, %esp
    movl %ebx, %esp
    popfl
    popal
    jmp *_probe_orig_throttle
