#!/usr/bin/env python3
"""Check a bounded daily-update CFG. Calls are opaque, assumed to return."""
import hashlib
import json
from pathlib import Path
import struct

import capstone
import pefile
from reverify.ledger import Ledger
from reverify.verifier import Claim, Verifier

ROOT = Path(__file__).resolve().parents[1]
data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
if digest != '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648':
    raise SystemExit('Binary profile mismatch')
pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
decoder.detail = True
start, stop = 0x685ead, 0x685f83
country_call, apply_call, economy_call = 0x685ed1, 0x685f53, 0x685f7e
# Expected destinations transcribed from an independent objdump inspection.
calls = {
    country_call: 0x5091a0, 0x685ed8: 0x685620, 0x685ef3: 0x685620,
    0x685f0f: 0x4f5bf0, 0x685f1c: 0x685620, 0x685f53: 0x4ba780,
    0x685f6e: 0x685620, economy_call: 0x489990,
}
branches = {
    0x685eb0: ('jle', 0x685ef1), 0x685eb2: ('jmp', 0x685ec0),
    0x685eef: ('jl', 0x685ec0), 0x685efd: ('jle', 0x685f1a),
    0x685f18: ('jl', 0x685f00), 0x685f35: ('jle', 0x685f6c),
    0x685f37: ('jmp', 0x685f40), 0x685f50: ('je', 0x685f58),
    0x685f6a: ('jl', 0x685f40),
}
claims = []
for address, target in calls.items():
    ident = f'tick_call_{address:x}'
    claims.extend([
        {'id': ident, 'kind': 'bytes_at', 'space': 'rva',
         'offset': hex(address - base),
         'expected': (b'\xe8' + struct.pack('<i', target - address - 5)).hex()},
        {'id': ident + '_decoded', 'kind': 'instructions', 'space': 'rva',
         'offset': hex(address - base), 'base': hex(address), 'arch': 'x86',
         'length': 5, 'mnemonics': ['call'], 'operands': [hex(target)],
         'depends_on': [ident]},
    ])
for address, (mnemonic, target) in branches.items():
    claims.append({'id': f'tick_branch_{address:x}', 'kind': 'instructions',
                   'space': 'rva', 'offset': hex(address - base), 'base': hex(address),
                   'arch': 'x86', 'length': 2, 'mnemonics': [mnemonic],
                   'operands': [hex(target)]})
report = Verifier(data).verify_all([Claim.from_dict(c) for c in claims])
if any(r['verdict'] != 'VERIFIED' for r in report['results']):
    raise SystemExit(json.dumps(report, indent=2))

# Recursively follow both sides of each direct branch. No speculative decoding
# across padding, no execution of callees, no inference of their memory effects.
nodes, pending = {}, [start]
while pending:
    address = pending.pop()
    if address == stop or address in nodes:
        continue
    assert start <= address < stop, hex(address)
    ins = next(decoder.disasm(pe.get_data(address - base, 15), address, count=1))
    following = address + ins.size
    edges = [following]
    if ins.group(capstone.CS_GRP_JUMP):
        assert ins.operands[0].type == capstone.x86.X86_OP_IMM
        target = ins.operands[0].imm
        edges = [target] if ins.mnemonic == 'jmp' else [following, target]
    elif ins.group(capstone.CS_GRP_CALL):
        assert calls.get(address) == ins.operands[0].imm, hex(address)
    else:
        assert not ins.group(capstone.CS_GRP_RET), hex(address)
    nodes[address] = {'va': hex(address), 'rva': hex(address - base),
                      'bytes': ins.bytes.hex(), 'mnemonic': ins.mnemonic,
                      'operands': ins.op_str, 'successors': [hex(e) for e in edges]}
    pending.extend(edges)

def reachable(origin, destination, blocked=None):
    todo, seen = [origin], set()
    while todo:
        address = todo.pop()
        if address == destination:
            return True
        if address in seen or address == blocked or address == stop:
            continue
        seen.add(address)
        todo.extend(int(e, 16) for e in nodes[address]['successors'])
    return False

assert reachable(start, country_call)
assert reachable(country_call + 5, economy_call)
assert not reachable(economy_call + 5, country_call)
assert reachable(start, economy_call, blocked=country_call)  # country loop can be skipped
assert reachable(country_call+5,apply_call)
assert reachable(apply_call+5,economy_call)
assert not reachable(apply_call+5,country_call)
assert not reachable(economy_call+5,apply_call)
assert reachable(start,economy_call,blocked=apply_call)  # consumer loop can be skipped
out = ROOT / 'evidence/generated/tick-path'
out.mkdir(parents=True, exist_ok=True)
for name, content in [('claims.json', claims), ('reverify.json', report), ('cfg.json', {
    'binary_sha256': digest, 'image_base': hex(base), 'entry_va': hex(start),
    'stop_va': hex(stop), 'nodes': [nodes[a] for a in sorted(nodes)],
    'status': 'confirmed bounded static CFG under the declared call-return model',
    'conclusions': {
        'country_call_can_precede_economy_call': True,
        'economy_call_cannot_reach_country_call_within_region': True,
        'country_call_can_be_skipped': True,
        'country_call_can_precede_pop_vector_consumer': True,
        'pop_vector_consumer_can_precede_economy_call': True,
        'consumer_cannot_reach_country_call_within_region': True,
        'economy_cannot_reach_consumer_within_region': True,
        'consumer_call_can_be_skipped': True,
    },
    'assumptions': ['Every opaque CALL returns to its next instruction.',
                    'Branches are considered feasible without path-constraint solving.',
                    'Callees may mutate state; their effects and interprocedural paths are outside this graph.'],
    'semantic_names': 'Country_DailyUpdate and Economy_Update remain external candidate names.',
})]:
    (out / name).write_text(json.dumps(content, indent=2) + '\n')
ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify')
ledger.record(report, session='tick-path-static')
ledger.save()
print(f'Tick path: {len(claims)} reverify checks; {len(nodes)} reachable instructions; bounded CFG checks pass.')
