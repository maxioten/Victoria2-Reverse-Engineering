.text
.globl _call_cr_sese_region

/* void __cdecl call_cr_sese_region(void *entry_va, void *self, void *country_mgr, int32_t *out_esp18) */
.balign 16
_call_cr_sese_region:
    pushl %ebx
    pushl %esi
    pushl %edi
    pushl %ebp
    /* Stack after 4 pushes:
     * +16: ret_eip
     * +20: entry_va
     * +24: self
     * +28: country_mgr
     * +32: out_esp18
     */
    movl 20(%esp), %eax         /* entry_va */
    movl 24(%esp), %ebx         /* self */
    movl 28(%esp), %edx         /* country_mgr */
    movl 32(%esp), %ecx         /* out_esp18 */
    pushl %ecx                  /* [esp_in + 0x60] */
    subl $0x60, %esp            /* esp_in */
    movl %edx, 0x28(%esp)       /* [esp_in + 0x28] = country_mgr */
    movl $0, 0x18(%esp)         /* clear output slot */
    jmp *%eax
