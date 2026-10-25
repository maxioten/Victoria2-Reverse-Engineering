#!/usr/bin/env python3
"""Recover consistent MSVC x86 RTTI candidates and byte-check selected CPop links."""
import hashlib
import json
from pathlib import Path
import re
import struct
import pefile
from reverify.ledger import Ledger
from reverify.verifier import Claim, Verifier

ROOT=Path(__file__).resolve().parents[1]
data=(ROOT.parent/'base-game/v2game.exe').read_bytes()
digest=hashlib.sha256(data).hexdigest()
if digest!='62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648':
    raise SystemExit('Binary profile mismatch')
pe=pefile.PE(data=data)
base=pe.OPTIONAL_HEADER.ImageBase
sections=[(base+s.VirtualAddress,s.get_data(),s.Characteristics) for s in pe.sections]
def region(address,size=1):
    return next(((start,raw,flags) for start,raw,flags in sections if start<=address and address+size<=start+len(raw)),None)
def read(address,size):
    section=region(address,size)
    if section is None: raise ValueError(hex(address))
    start,raw,_=section
    return raw[address-start:address-start+size]
def executable(address):
    found=region(address)
    return found is not None and bool(found[2]&0x20000000)
def words(address,count): return struct.unpack('<'+'I'*count,read(address,count*4))
types={}
for match in re.finditer(rb'\.\?A[UV][!-~]{1,2048}\x00',data):
    if match.start()<8:continue
    try:
        address=base+pe.get_rva_from_offset(match.start())-8
        section=region(address,len(match.group())+8)
        if address%4 or section is None or section[2]&0x20000000:continue
        info,spare=words(address,2)
        if spare!=0 or region(info,4) is None:continue
    except (ValueError,pefile.PEFormatError):continue
    types[address]={'type_descriptor_va':hex(address),'type_info_vftable_word':hex(info),
                    'decorated_name':match.group()[:-1].decode('ascii')}

locators={}
for start,raw,flags in sections:
    if flags&0x20000000 or not flags&0x40000000:continue
    for offset in range(12,len(raw)-7,4):
        td=struct.unpack_from('<I',raw,offset)[0]
        if td not in types:continue
        col=start+offset-12
        try:
            signature,obj_offset,constructor_offset,_,hierarchy=words(col,5)
            if signature!=0:continue
            h_signature,h_attributes,count,array=words(hierarchy,4)
            if h_signature!=0 or not 1<=count<=512:continue
            base_records=[]
            for bcd in words(array,count):
                btd,contained,mdisp,pdisp,vdisp,attributes=struct.unpack('<2I3iI',read(bcd,24))
                if btd not in types:raise ValueError('Unknown base type descriptor')
                base_records.append({'descriptor_va':hex(bcd),'type_descriptor_va':hex(btd),
                    'decorated_name':types[btd]['decorated_name'],'contained_bases':contained,
                    'mdisp':mdisp,'pdisp':pdisp,'vdisp':vdisp,'attributes':hex(attributes)})
            if not base_records or base_records[0]['type_descriptor_va']!=hex(td):continue
        except (ValueError,struct.error):continue
        locators[col]={'locator_va':hex(col),'type_descriptor_va':hex(td),'decorated_name':types[td]['decorated_name'],
            'object_offset':obj_offset,'constructor_displacement_offset':constructor_offset,
            'hierarchy_va':hex(hierarchy),'hierarchy_attributes':hex(h_attributes),'base_array_va':hex(array),
            'base_records':base_records,'vtables':[]}

for start,raw,flags in sections:
    if flags&0x20000000 or not flags&0x40000000:continue
    for offset in range(0,len(raw)-7,4):
        locator=struct.unpack_from('<I',raw,offset)[0]
        if locator not in locators:continue
        table=start+offset+4
        entries=[]
        for slot in range(512):
            try: target=words(table+slot*4,1)[0]
            except ValueError:break
            if not executable(target):break
            entries.append(hex(target))
        if entries:
            locators[locator]['vtables'].append({'vtable_va':hex(table),'contiguous_executable_entries':entries,
                'length_is_lower_bound_or_candidate':True})

selected={}
for entry in locators.values():
    if entry['decorated_name'] in ('.?AVCPop@@', '.?AVCRegiment@@', '.?AVCSubUnit@@') or 'CDataSpread' in entry['decorated_name']:
        selected[entry['decorated_name']]=entry
assert selected['.?AVCPop@@']['vtables'][0]['vtable_va']=='0xe36428'
spread_name='.?AV?$CDataSpread@V?$fixed_point@_J$0DA@$0P@@fpml@@H$0GE@@@'
assert selected[spread_name]['vtables'][0]['vtable_va']=='0xdfd2cc'
assert selected['.?AVCRegiment@@']['vtables'][0]['vtable_va']=='0xdf8884'
assert selected['.?AVCSubUnit@@']['vtables'][0]['vtable_va']=='0xe029ec'

claims=[
    {'id':'rtti_cpop_name','kind':'bytes_at','space':'rva','offset':'0xb11418','expected':b'.?AVCPop@@\0'.hex()},
    {'id':'rtti_spread_name','kind':'bytes_at','space':'rva','offset':'0xb11448','expected':(spread_name+'\0').encode().hex()},
    {'id':'rtti_cpop_locator','kind':'bytes_at','space':'rva','offset':'0xa67228',
     'expected':struct.pack('<5I',0,0,0,0xf11410,0xe4d0c8).hex()},
    {'id':'rtti_cpop_vtable_locator_word','kind':'u32_at','space':'rva','offset':'0xa36424','expected':0xe67228},
    {'id':'rtti_spread_locator','kind':'bytes_at','space':'rva','offset':'0xa4d104',
     'expected':struct.pack('<5I',0,0,0,0xf11440,0xe4d118).hex()},
    {'id':'rtti_spread_vtable_locator_word','kind':'u32_at','space':'rva','offset':'0x9fd2c8','expected':0xe4d104},
    {'id':'rtti_regiment_name','kind':'bytes_at','space':'rva','offset':'0xb107fc',
     'expected':b'.?AVCRegiment@@\0'.hex()},
    {'id':'rtti_regiment_locator','kind':'bytes_at','space':'rva','offset':'0xa4b3e4',
     'expected':struct.pack('<5I',0,0,0,0xf107f4,0xe4b3f8).hex()},
    {'id':'rtti_regiment_vtable_locator_word','kind':'u32_at','space':'rva','offset':'0x9f8880','expected':0xe4b3e4},
    {'id':'rtti_regiment_virtual_destructor','kind':'u32_at','space':'rva','offset':'0x9f8884','expected':0x4471b0},
    {'id':'rtti_subunit_name','kind':'bytes_at','space':'rva','offset':'0xb107e4',
     'expected':b'.?AVCSubUnit@@\0'.hex()},
    {'id':'rtti_subunit_locator','kind':'bytes_at','space':'rva','offset':'0xa50694',
     'expected':struct.pack('<5I',0,0,0,0xf107dc,0xe4b438).hex()},
    {'id':'rtti_subunit_vtable_locator_word','kind':'u32_at','space':'rva','offset':'0xa029e8','expected':0xe50694},
]
for address,length,mnemonic,operand in (
    (0x4a8237,5,'call','0x955ae0'),
    (0x4a823c,4,'test','byte ptr [ebp + 8], 1'),
    (0x4a8243,5,'call','0xaae91b'),
    (0x4a824f,3,'ret','4'),
    (0x9554a9,6,'mov','dword ptr [edi], 0xe36428'),
    (0x955503,5,'call','0x955980'),
    (0x955519,5,'call','0x955980'),
    (0x9559ac,6,'mov','dword ptr [esi], 0xdfd2cc'),
    (0x4be161,5,'push','0x288'),
    (0x4be183,5,'call','0x955450'),
    (0x4be188,6,'mov','dword ptr [esi + 0x278], ebx'),
    (0x4be18e,10,'mov','dword ptr [esi + 0x27c], 0'),
    (0x4be198,7,'mov','byte ptr [esi + 0x280], 0'),
    (0x4be340,6,'add','esi, 0x278'),
    (0x9557cc,6,'mov','dword ptr [edi + 0x274], eax'),
    (0x955b2e,5,'call','0x68a900'),
    (0x68a9bb,5,'call','0x4be200'),
    (0x68a9c0,7,'mov','dword ptr [ebx + 0x30], 0'),
    (0x68a9fe,2,'mov','edx, dword ptr [eax]'),
    (0x68aa00,2,'push','1'),
    (0x68aa04,2,'call','edx'),
    (0x4471b6,5,'call','0x5be2b0'),
    (0x4471c2,5,'call','0xaae91b'),
    (0x5be2cf,6,'mov','dword ptr [esi], 0xe029ec'),
    (0x5be2e7,5,'call','0x4be200'),
    (0x68f05e,5,'call','0xaae480'),
):
    claims.append({'id':f'cpop_rtti_code_link_{address:x}','kind':'instructions','space':'rva',
                   'offset':hex(address-base),'base':hex(address),'arch':'x86','length':length,
                   'mnemonics':[mnemonic],'operands':[operand]})
verification=Verifier(data).verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict']=='VERIFIED' for r in verification['results']), [
    r for r in verification['results'] if r['verdict'] != 'VERIFIED']
out=ROOT/'evidence/generated/rtti'
out.mkdir(parents=True,exist_ok=True)
for name,value in [('claims.json',claims),('reverify.json',verification),('selected.json',{
    'binary_sha256':digest,'preferred_image_base':hex(base),'selected':selected,
    'schema_source':'Ghidra 12.1.4 installed Base-src.zip RTTI1DataType / RTTI4DataType; x86 pointer form',
    'scope':'Literal RTTI names and consistent pointer chains. Class sizes, field meaning, complete vtable '
            'lengths, original source, runtime object types and unlisted methods are not established.',
}),('inventory.json',{'binary_sha256':digest,'type_descriptor_candidates':list(types.values()),
    'consistent_locator_candidates':list(locators.values()),'limits':'Bounded ASCII name scan, signature-zero '
    'x86 RTTI, readable section pointers, known base descriptors, up to 512 bases/slots. RTTI may be absent; '
    'candidate inventory is not complete engine coverage or proof of all function boundaries.'})]:
    (out/name).write_text(json.dumps(value,indent=2)+'\n')
ledger=Ledger.for_bytes(data,directory=ROOT/'.reverify')
ledger.record(verification,session='rtti-cpop-dataspread-pointer-chains')
ledger.save()
vtable_count=sum(len(col['vtables']) for col in locators.values())
print(f'RTTI: {len(types)} descriptor candidates, {len(locators)} consistent locators, {vtable_count} vtable candidates; selected bytes pass.')
