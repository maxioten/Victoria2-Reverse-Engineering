#!/usr/bin/env python3
"""Verify CCountryEventEffect::Execute (0x0088D370), vtables and delayed queuing."""
import hashlib
import json
from pathlib import Path
import struct
import capstone
import pefile
import unicorn
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX,
    UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI,
)
from reverify.ledger import Ledger
from reverify.verifier import Claim, Verifier
from event_spawn_model import compute_event_spawn

ROOT = Path(__file__).resolve().parents[1]
data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
image = pe.get_memory_mapped_image()
base = 0x400000

claims = []

# 1. Vtable entries for CCountryEventEffect and CProvinceEventEffect
claims.append({
    'id': 'vtable_country_event_effect_execute', 'kind': 'bytes_at', 'space': 'rva',
    'offset': hex(0x00E2B468 - base),
    'expected': '70d38800'  # 0x0088D370
})

claims.append({
    'id': 'vtable_province_event_effect_execute', 'kind': 'bytes_at', 'space': 'rva',
    'offset': hex(0x00E2B4A0 - base),
    'expected': 'b0d68800'  # 0x0088D6B0
})

# 2. Key instructions in CCountryEventEffect::Execute (0x0088D370)
expected_execute_instructions = (
    (0x0088D370, 1, 'push', 'ebp'),
    (0x0088D37F, 3, 'mov', 'eax, dword ptr [edi + 0x40]'),
    (0x0088D382, 6, 'imul', 'eax, eax, 0x343fd'),
    (0x0088D388, 5, 'add', 'eax, 0x269ec3'),
    (0x0088D391, 6, 'imul', 'eax, eax, 0x343fd'),
    (0x0088D397, 5, 'add', 'eax, 0x269ec3'),
    (0x0088D39C, 3, 'mov', 'dword ptr [edi + 0x40], eax'),
    (0x0088D3A5, 6, 'and', 'ecx, 0x7fff'),
    (0x0088D3AB, 5, 'and', 'eax, 0x7fff'),
    (0x0088D3B0, 3, 'imul', 'eax, ecx'),
    (0x0088D3B8, 5, 'call', '0x8a8650'),
    (0x0088D3CF, 5, 'call', '0x8a8dc0'),
    (0x0088D3E7, 3, 'mov', 'eax, dword ptr [ebx + 0x20]'),
    (0x0088D3EE, 6, 'mov', 'ecx, dword ptr [0x1258a98]'),
    (0x0088D3F4, 8, 'mov', 'dword ptr [esp + 0x10], 0x27'),
    (0x0088D408, 5, 'call', '0x9c1d40'),
    (0x0088D413, 3, 'mov', 'ebx, dword ptr [ebx + 0x24]'),
    (0x0088D416, 2, 'test', 'ebx, ebx'),
    (0x0088D418, 2, 'jg', '0x88d439'),
    (0x0088D420, 5, 'call', '0x8a6620'),
    (0x0088D42B, 5, 'call', '0x8a8120'),
    (0x0088D436, 3, 'ret', '8'),
    (0x0088D439, 6, 'mov', 'ecx, dword ptr [0x12587e4]'),
    (0x0088D451, 5, 'call', '0x540a70'),
    (0x0088D45C, 3, 'ret', '8'),
)

for address, length, mnemonic, operand in expected_execute_instructions:
    claims.append({
        'id': f'spawn_ins_{address:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(address - base), 'base': hex(address), 'arch': 'x86',
        'length': length, 'mnemonics': [mnemonic], 'operands': [operand]
    })

# 3. Key instructions in CCountry::AddDelayedEvent (0x00540A70)
expected_delayed_instructions = (
    (0x00540A70, 1, 'push', 'ebp'),
    (0x00540A75, 2, 'push', '0x58'),
    (0x00540A77, 5, 'call', '0xaae9af'),
    (0x00540A91, 7, 'mov', 'dword ptr [esi + 4], 0x18d'),
    (0x00540A98, 6, 'mov', 'dword ptr [esi], 0xe2c858'),
    (0x00540A9E, 5, 'call', '0x8a88d0'),
    (0x00540AA6, 3, 'mov', 'dword ptr [esi + 0x54], ecx'),
    (0x00540AB0, 3, 'add', 'edi, 0x68'),
    (0x00540AB9, 5, 'call', '0x68f390'),
    (0x00540AC1, 3, 'ret', '0x10'),
)

for address, length, mnemonic, operand in expected_delayed_instructions:
    claims.append({
        'id': f'add_delayed_ins_{address:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(address - base), 'base': hex(address), 'arch': 'x86',
        'length': length, 'mnemonics': [mnemonic], 'operands': [operand]
    })

verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls
wrong = dict(claims[0], id='negative_control', expected='99999999')
dependent = dict(claims[1], id='negative_dependent', depends_on=['negative_control'])
controls = verifier.verify_all([Claim.from_dict(wrong), Claim.from_dict(dependent)])
assert [r['verdict'] for r in controls['results']] == ['REFUTED', 'INVALIDATED']

# 4. Unicorn dynamic emulation of CCountryEventEffect::Execute (0x0088D370)
return_addr = 0x55555555

def simulate_spawn_execution(seed: int, delay: int, event_id: int, tag_index: int, registry_has_event: bool):
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    uc.mem_map(0x400000, 0x1100000, unicorn.UC_PROT_ALL)
    uc.mem_write(0x400000, image)

    # Map zero-page for safe SEH / FS reads
    uc.mem_map(0, 0x1000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
    # Map stack
    stack_base = 0x200000
    stack_size = 0x10000
    uc.mem_map(stack_base, stack_size, unicorn.UC_PROT_ALL)
    esp = stack_base + stack_size - 0x100

    # Heap structures
    heap_base = 0x1600000
    uc.mem_map(heap_base, 0x20000, unicorn.UC_PROT_ALL)

    # Effect object (this)
    this_ptr = heap_base + 0x100
    uc.mem_write(this_ptr + 0x20, struct.pack('<I', event_id))
    uc.mem_write(this_ptr + 0x24, struct.pack('<i', delay))

    # Scope object (arg0)
    scope_ptr = heap_base + 0x200
    uc.mem_write(scope_ptr + 0x40, struct.pack('<I', seed))
    # Sub-block at scope + 0x24
    sub_block = heap_base + 0x300
    uc.mem_write(sub_block + 0x08, struct.pack('<I', 0x1111))
    uc.mem_write(sub_block + 0x0C, struct.pack('<I', 0x2222))
    uc.mem_write(sub_block + 0x10, struct.pack('<I', 0x3333))
    uc.mem_write(scope_ptr + 0x24, struct.pack('<I', sub_block))
    uc.mem_write(scope_ptr + 0x08, struct.pack('<I', 0x4444))
    uc.mem_write(scope_ptr + 0x0C, struct.pack('<I', tag_index))

    # Global Object Registry at 0x01258A98
    registry_ptr = heap_base + 0x400
    uc.mem_write(0x01258A98, struct.pack('<I', registry_ptr))

    # Event object in registry
    event_ptr = heap_base + 0x500 if registry_has_event else 0

    # CountryManager at 0x012587E4
    cm_ptr = heap_base + 0x600
    country_table = heap_base + 0x700
    uc.mem_write(0x012587E4, struct.pack('<I', cm_ptr))
    uc.mem_write(cm_ptr + 4, struct.pack('<I', country_table))
    target_country_ptr = heap_base + 0x800
    uc.mem_write(country_table + tag_index * 4, struct.pack('<I', target_country_ptr))

    # Mocked callee tracking
    calls_recorded = []

    # Install stubs at callee entry points
    # 0x008A8650 (initializes event payload with roll): RET 4
    uc.mem_write(0x008A8650, b'\xc2\x04\x00')
    # 0x008A8DC0: RET
    uc.mem_write(0x008A8DC0, b'\x8b\x47\x24\x8d\x40\x08\xc3')  # returns eax = sub_block + 8
    # 0x009C1D40: Registry Lookup returns event_ptr
    # mov eax, event_ptr; ret
    uc.mem_write(0x009C1D40, b'\xb8' + struct.pack('<I', event_ptr) + b'\xc3')
    # 0x008A6620 (context init): RET
    uc.mem_write(0x008A6620, b'\x8b\x44\x24\x04\xc3')  # returns eax = context
    # 0x008A8120 (Event_Fire): hook
    fire_stub = 0x008A8120
    # 0x00540A70 (AddDelayedEvent): hook
    delayed_stub = 0x00540A70

    def hook_code(uc, address, size, user_data):
        if address == 0x008A8650:
            # stack has [esp + 4] = roll
            roll_val = struct.unpack('<I', uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 4, 4))[0]
            calls_recorded.append(('8A8650', roll_val))
        elif address == fire_stub:
            ecx_val = uc.reg_read(UC_X86_REG_ECX)
            esp_val = uc.reg_read(UC_X86_REG_ESP)
            ctx_arg = struct.unpack('<I', uc.mem_read(esp_val + 4, 4))[0]
            calls_recorded.append(('FIRE', ecx_val, ctx_arg))
            # Return cleanly from Fire stub (ret 4)
            uc.reg_write(UC_X86_REG_ESP, esp_val + 4)
            uc.reg_write(unicorn.x86_const.UC_X86_REG_EIP, struct.unpack('<I', uc.mem_read(esp_val, 4))[0])
        elif address == delayed_stub:
            esp_val = uc.reg_read(UC_X86_REG_ESP)
            country_arg = struct.unpack('<I', uc.mem_read(esp_val + 4, 4))[0]
            event_arg = struct.unpack('<I', uc.mem_read(esp_val + 8, 4))[0]
            inst_arg = struct.unpack('<I', uc.mem_read(esp_val + 12, 4))[0]
            delay_arg = struct.unpack('<i', uc.mem_read(esp_val + 16, 4))[0]
            calls_recorded.append(('DELAYED', country_arg, event_arg, inst_arg, delay_arg))
            # Return cleanly from AddDelayedEvent stub (ret 0x10)
            uc.reg_write(UC_X86_REG_ESP, esp_val + 20)
            uc.reg_write(unicorn.x86_const.UC_X86_REG_EIP, struct.unpack('<I', uc.mem_read(esp_val, 4))[0])

    hook = uc.hook_add(unicorn.UC_HOOK_CODE, hook_code)

    # Set up call frame for CCountryEventEffect::Execute(scope_ptr, 0)
    # Stack layout: [esp] = return_addr, [esp+4] = scope_ptr, [esp+8] = 0
    uc.mem_write(esp, struct.pack('<III', return_addr, scope_ptr, 0))
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_ECX, this_ptr)

    uc.emu_start(0x0088D370, return_addr, timeout=2000000)

    # Read back updated seed from scope
    final_seed = struct.unpack('<I', uc.mem_read(scope_ptr + 0x40, 4))[0]

    return {
        'final_seed': final_seed,
        'calls': calls_recorded,
        'target_country_ptr': target_country_ptr,
        'event_ptr': event_ptr,
    }

# Run test battery
fixtures = [
    # (seed, delay, event_id, tag_index, registry_has_event)
    (12345, 0, 100, 3, True),
    (12345, -1, 100, 3, True),
    (12345, 5, 100, 3, True),
    (12345, 30, 200, 1, True),
    (54321, 0, 300, 0, False),
    (99999, 10, 400, 2, False),
]
for s in (1, 42, 1000, 0x12345678, 0xABCDEF01):
    for d in (-10, 0, 1, 7, 30, 365):
        for reg in (True, False):
            fixtures.append((s, d, (s ^ d) & 0xFFFF, (s + d) & 0x7, reg))

fixture_count = 0
for seed, delay, event_id, tag_index, reg_has in fixtures:
    expected_seed, expected_roll, exp_action, exp_args = compute_event_spawn(
        seed, delay, event_id, tag_index, reg_has
    )
    result = simulate_spawn_execution(seed, delay, event_id, tag_index, reg_has)

    assert result['final_seed'] == expected_seed, (
        f"Seed mismatch: {result['final_seed']} vs {expected_seed}"
    )

    # Check roll passed to 8A8650
    roll_calls = [c[1] for c in result['calls'] if c[0] == '8A8650']
    assert len(roll_calls) == 1 and roll_calls[0] == expected_roll, (
        f"Roll mismatch: {roll_calls} vs {expected_roll}"
    )

    if exp_action == "NONE":
        assert not any(c[0] in ('FIRE', 'DELAYED') for c in result['calls']), (
            f"Expected no dispatch, got {result['calls']}"
        )
    elif exp_action == "FIRE_IMMEDIATE":
        fire_calls = [c for c in result['calls'] if c[0] == 'FIRE']
        assert len(fire_calls) == 1, f"Expected 1 FIRE call, got {fire_calls}"
        assert fire_calls[0][1] == result['event_ptr'], "Event ptr mismatch in FIRE"
    elif exp_action == "ENQUEUE_DELAYED":
        delay_calls = [c for c in result['calls'] if c[0] == 'DELAYED']
        assert len(delay_calls) == 1, f"Expected 1 DELAYED call, got {delay_calls}"
        country_arg, event_arg, inst_arg, delay_arg = delay_calls[0][1:]
        assert country_arg == result['target_country_ptr'], "Country ptr mismatch"
        assert event_arg == result['event_ptr'], "Event ptr mismatch in DELAYED"
        assert delay_arg == delay, "Delay value mismatch"

    fixture_count += 1

out = ROOT / 'evidence/generated/event-spawn'
out.mkdir(parents=True, exist_ok=True)
(out / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out / 'emulation.json').write_text(json.dumps({
    'total_fixtures': fixture_count,
    'mismatches': 0,
}, indent=2) + '\n')

ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify')
ledger.record(report, session='event-spawn-dispatch')
ledger.save()

print(f"Event spawn: {len(claims)} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Event spawn emulation: {fixture_count} fixtures executed, 0 mismatches against event_spawn_model.")
