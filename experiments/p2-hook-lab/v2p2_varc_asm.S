.text

.globl _v2p2_wrap_set_owner
.globl _v2p2_wrap_country_reset
.globl _v2p2_wrap_world_change_tag

/* void __thiscall CProvince::SetOwner(CProvince *this, CTag *new_tag, uint32_t a2, uint32_t a3, uint8_t arg4) -> ret 0x10 */
.balign 16
_v2p2_wrap_set_owner:
    pushl %ebx
    pushl %esi
    movl %ecx, %ebx             /* prov */
    movl 24(%esp), %esi         /* arg4 */
    xorl %eax, %eax
    testl $0xFF, %esi
    jnz 1f
    movl 0x12C(%ebx), %eax      /* old_id = *(prov + 0x12C) */
1:
    pushl %eax                  /* save old_id */
    pushl 28(%esp)              /* arg4 */
    pushl 28(%esp)              /* arg3 */
    pushl 28(%esp)              /* arg2 */
    pushl 28(%esp)              /* new_tag */
    movl %ebx, %ecx
    call *_v2p2_orig_set_owner  /* callee pops 0x10 */
    popl %ecx                   /* old_id */
    testl $0xFF, %esi
    jnz 2f
    pushl %eax                  /* preserve EAX */
    pushl %ecx                  /* old_id */
    pushl %ebx                  /* prov */
    call _v2p2_on_post_set_owner
    addl $8, %esp
    popl %eax
2:
    popl %esi
    popl %ebx
    ret $0x10

/* void __stdcall CCountry::Reset(CCountry *country) -> ret 4 */
.balign 16
_v2p2_wrap_country_reset:
    pushl %ebx
    movl 8(%esp), %ebx          /* country */
    pushl %ebx
    call *_v2p2_orig_country_reset
    pushl %eax
    pushl %ebx
    call _v2p2_on_post_country_reset
    addl $4, %esp
    popl %eax
    popl %ebx
    ret $4

/* void __stdcall CWorld::ChangeTag(CWorld *world, CTag *tag1, CTag *tag2) -> ret 0xC */
.balign 16
_v2p2_wrap_world_change_tag:
    pushl %ebx
    pushl %esi
    pushl %edi
    movl 20(%esp), %esi         /* tag1 */
    movl 24(%esp), %edi         /* tag2 */
    xorl %ebx, %ebx
    xorl %edx, %edx
    testl %esi, %esi
    jz 1f
    movl 4(%esi), %ebx          /* id1 = *(tag1 + 4) */
1:
    testl %edi, %edi
    jz 2f
    movl 4(%edi), %edx          /* id2 = *(tag2 + 4) */
2:
    pushl %edx                  /* save id2 */
    pushl %ebx                  /* save id1 */
    call _v2p2_on_pre_world_change_tag
    pushl 32(%esp)              /* tag2 */
    pushl 32(%esp)              /* tag1 */
    pushl 32(%esp)              /* world */
    call *_v2p2_orig_world_change_tag
    popl %ebx                   /* id1 */
    popl %edx                   /* id2 */
    pushl %eax                  /* preserve EAX */
    pushl %edx                  /* id2 */
    pushl %ebx                  /* id1 */
    call _v2p2_on_post_world_change_tag
    addl $8, %esp
    popl %eax
    popl %edi
    popl %esi
    popl %ebx
    ret $0xC
