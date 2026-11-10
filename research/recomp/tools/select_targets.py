import json, os
from common import BIN, ANALYSIS
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_MEM, X86_OP_IMM, X86_REG_FS, X86_REG_GS
from tools.lift.lift32 import Lifter

pe=pefile.PE(str(BIN), fast_load=True)
img=pe.get_memory_mapped_image()
base=pe.OPTIONAL_HEADER.ImageBase
funcs=json.load(open(ANALYSIS/'functions.json'))['functions']
md=Cs(CS_ARCH_X86, CS_MODE_32); md.detail=True
BAD={'call','int','int3','sysenter','syscall','cpuid','rdtsc','rdmsr','wrmsr','hlt','in','out','iret','iretd','fsin','fcos','fsincos','fpatan','fyl2x','f2xm1','fscale','fxtract','fyl2xp1','fninit','finit','fwait','wait'}
cands=[]; rejected={}
for f in funcs:
    if f.get('is_thunk') or f.get('calls_to'): continue
    size=f['size']
    if not (8 <= size <= 180): continue
    va=f['address']; off=va-base
    if off < 0 or off+size > len(img): continue
    code=bytes(img[off:off+size])
    ins=list(md.disasm(code, va))
    if not ins or sum(i.size for i in ins)!=size: continue
    reason=None
    for i in ins:
        m=i.mnemonic
        if m in BAD: reason=f'bad:{m}'; break
        if m=='ret' and i.op_str: reason='ret-imm'; break
        if m in ('jmp','ljmp','loop','loope','loopne','jecxz','jrcxz') or (m.startswith('j') and m not in ('jmp',)):
            reason='branch'; break
        for op in i.operands:
            if op.type==X86_OP_MEM:
                if op.mem.segment in (X86_REG_FS, X86_REG_GS): reason='fs/gs'; break
                if op.mem.base==0:
                    a=op.mem.disp
                    if not (0 <= a < 0x01500000): reason='abs-out'; break
        if reason: break
    if reason:
        rejected[reason]=rejected.get(reason,0)+1; continue
    try:
        lifter=Lifter(precise_carry=False)
        lifter._labels=set(); lifter._jump_targets=set(); lifter._flag_state=None
        body=[]
        for i in ins:
            body.extend(lifter.lift_instruction(i))
        if any('UNIMPLEMENTED' in x for x in body): reason='lift-unimpl'
        else:
            mn={i.mnemonic for i in ins}
            feats=[]
            if any(x.startswith('f') for x in mn): feats.append('x87')
            if any(x.startswith(('movaps','movups','addps','mulps','xorps','pxor','movd','movq','padd','pshuf','cvtsi','cvtss','cvtt','comiss','ucomiss')) for x in mn): feats.append('sse/mmx')
            if any(x.startswith(('rep','movs','stos','lods','scas','cmps')) for x in mn): feats.append('string')
            cands.append({'address':va,'address_hex':f'0x{va:08X}','size':size,'insns':len(ins),
                          'mnemonics':sorted(mn),'features':feats,'bytes':code.hex(),
                          'entry_kind':f.get('entry_kind')})
    except Exception as e:
        reason='lift-exc:'+type(e).__name__
    if reason:
        rejected[reason]=rejected.get(reason,0)+1
print('candidates',len(cands),'rejected',rejected)
# Pick 40: spread across address, prefer feature diversity and small/medium size
cands.sort(key=lambda c:(c['address']))
selected=[]
# first, one per feature group
for feat in ('x87','sse/mmx','string'):
    for c in cands:
        if feat in c['features'] and c not in selected:
            selected.append(c); break
# then evenly spaced
step=max(1,len(cands)//(40-len(selected)))
for c in cands[::step]:
    if len(selected)>=40: break
    if c not in selected: selected.append(c)
for c in cands:
    if len(selected)>=40: break
    if c not in selected: selected.append(c)
selected.sort(key=lambda c:c['address'])
json.dump(selected,open(ANALYSIS/'difftest_targets.json','w'),indent=1)
print('selected',len(selected))
for c in selected:
    print(f"{c['address_hex']} size={c['size']:3d} insns={c['insns']:2d} feat={','.join(c['features']) or '-'} mn={','.join(c['mnemonics'][:8])}")
