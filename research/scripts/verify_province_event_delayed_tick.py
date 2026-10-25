#!/usr/bin/env python3
"""Verify CProvince::ProcessDelayedEvents (0x004B1E16..0x004B1FA5)."""
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
from province_event_delayed_tick_model import ProvinceDelayedEventEntry, process_province_delayed_events_tick

ROOT = Path(__file__).resolve().parents[1]
data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
image = pe.get_memory_mapped_image()
base = 0x400000

claims = []

# 1. Instruction claims for delayed event loop in CProvince::DailyUpdate
expected_instructions = (
    (0x004B1E16, 6, 'mov', 'edx, dword ptr [edi + 0x384]'),
    (0x004B1E1C, 4, 'mov', 'dword ptr [esp + 0x28], edx'),
    (0x004B1E20, 4, 'mov', 'eax, dword ptr [esp + 0x28]'),
    (0x004B1E24, 6, 'cmp', 'eax, dword ptr [edi + 0x384]'),
    (0x004B1E2A, 6, 'jb', '0x4b1fa5'),
    (0x004B1E30, 6, 'cmp', 'eax, dword ptr [edi + 0x388]'),
    (0x004B1E36, 6, 'jae', '0x4b1fa5'),
    (0x004B1E3C, 2, 'mov', 'ecx, eax'),
    (0x004B1E3E, 2, 'mov', 'ebx, dword ptr [ecx]'),
    (0x004B1E40, 3, 'dec', 'dword ptr [ebx + 0x54]'),
    (0x004B1E43, 3, 'add', 'ecx, 4'),
    (0x004B1E46, 4, 'cmp', 'dword ptr [ebx + 0x54], 0'),
    (0x004B1E4A, 4, 'mov', 'dword ptr [esp + 0x28], ecx'),
    (0x004B1E4E, 2, 'jg', '0x4b1e20'),
    (0x004B1E56, 3, 'mov', 'eax, dword ptr [ebx + 8]'),
    (0x004B1F0A, 3, 'lea', 'eax, [ebx + 0xc]'),
    (0x004B1F13, 5, 'call', '0x8a8120'),
    (0x004B1F18, 6, 'mov', 'edx, dword ptr [edi + 0x384]'),
    (0x004B1F1E, 6, 'mov', 'eax, dword ptr [edi + 0x388]'),
    (0x004B1F69, 5, 'call', '0xaae480'),
    (0x004B1F90, 6, 'mov', 'dword ptr [edi + 0x388], eax'),
    (0x004B1F9E, 2, 'call', 'edx'),
    (0x004B1FA0, 5, 'jmp', '0x4b1e20'),
    (0x004B1FA9, 1, 'pop', 'edi'),
    (0x004B1FB6, 1, 'ret', ''),
)

for address, length, mnemonic, operand in expected_instructions:
    claims.append({
        'id': f'prov_delayed_tick_ins_{address:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(address - base), 'base': hex(address), 'arch': 'x86',
        'length': length, 'mnemonics': [mnemonic], 'operands': [operand] if operand else []
    })

verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls
wrong = dict(claims[0], id='negative_control', operands=['edx, dword ptr [edi + 0x380]'])
dependent = dict(claims[1], id='negative_dependent', depends_on=['negative_control'])
controls = verifier.verify_all([Claim.from_dict(wrong), Claim.from_dict(dependent)])
assert [r['verdict'] for r in controls['results']] == ['REFUTED', 'INVALIDATED']

# 2. Unicorn dynamic emulation of 0x004B1E16..0x004B1FA9
def simulate_province_delayed_tick(events):
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    uc.mem_map(0x400000, 0x1100000, unicorn.UC_PROT_ALL)
    uc.mem_write(0x400000, image)

    uc.mem_map(0, 0x1000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
    stack_base = 0x200000
    stack_size = 0x10000
    uc.mem_map(stack_base, stack_size, unicorn.UC_PROT_ALL)
    ebp = stack_base + stack_size - 0x200
    esp = ebp - 0x80

    heap_base = 0x1600000
    uc.mem_map(heap_base, 0x20000, unicorn.UC_PROT_ALL)

    prov_ptr = heap_base + 0x100
    vec_buf = heap_base + 0x400
    event_obj_ptrs = []

    # Fake vtable for deleting destructor at heap_base + 0x2000
    fake_vtable = heap_base + 0x2000
    destructor_stub = 0x008321B0
    uc.mem_write(fake_vtable, struct.pack('<I', destructor_stub))

    for i, ev in enumerate(events):
        entry_ptr = heap_base + 0x800 + i * 0x100
        uc.mem_write(entry_ptr + 0x00, struct.pack('<I', fake_vtable))
        uc.mem_write(entry_ptr + 0x04, struct.pack('<I', 0x18D))
        uc.mem_write(entry_ptr + 0x08, struct.pack('<I', ev.event_id))
        uc.mem_write(entry_ptr + 0x54, struct.pack('<i', ev.delay))
        event_obj_ptrs.append(entry_ptr)
        uc.mem_write(vec_buf + i * 4, struct.pack('<I', entry_ptr))

    vec_begin = vec_buf
    vec_end = vec_buf + len(events) * 4
    vec_cap = vec_end

    uc.mem_write(prov_ptr + 0x384, struct.pack('<III', vec_begin, vec_end, vec_cap))

    # Pre-populate global context ptr at 0x1319B80 so it doesn't allocate huge state
    fake_context = heap_base + 0x3000
    uc.mem_write(0x01319B80, struct.pack('<I', fake_context))

    fired_ids = []
    destroyed_ptrs = []

    def hook_code(uc, address, size, user_data):
        if address == 0x008A8120:  # Event_Fire (ret 8)
            ev_id = uc.reg_read(UC_X86_REG_ECX)
            fired_ids.append(ev_id)
            esp_val = uc.reg_read(UC_X86_REG_ESP)
            ret_target = struct.unpack('<I', uc.mem_read(esp_val, 4))[0]
            uc.reg_write(UC_X86_REG_ESP, esp_val + 12)
            uc.reg_write(unicorn.x86_const.UC_X86_REG_EIP, ret_target)
        elif address == 0x00AAE480:  # memmove(dst, src, n)
            esp_val = uc.reg_read(UC_X86_REG_ESP)
            dst = struct.unpack('<I', uc.mem_read(esp_val + 4, 4))[0]
            src = struct.unpack('<I', uc.mem_read(esp_val + 8, 4))[0]
            n = struct.unpack('<I', uc.mem_read(esp_val + 12, 4))[0]
            if n > 0:
                data = uc.mem_read(src, n)
                uc.mem_write(dst, bytes(data))
            ret_target = struct.unpack('<I', uc.mem_read(esp_val, 4))[0]
            uc.reg_write(UC_X86_REG_ESP, esp_val + 4)
            uc.reg_write(unicorn.x86_const.UC_X86_REG_EIP, ret_target)
        elif address == destructor_stub:  # CDelayedEvent dtor
            ecx_val = uc.reg_read(UC_X86_REG_ECX)
            destroyed_ptrs.append(ecx_val)
            esp_val = uc.reg_read(UC_X86_REG_ESP)
            ret_target = struct.unpack('<I', uc.mem_read(esp_val, 4))[0]
            # scalar deleting destructor ret 4
            uc.reg_write(UC_X86_REG_ESP, esp_val + 8)
            uc.reg_write(unicorn.x86_const.UC_X86_REG_EIP, ret_target)

    hook = uc.hook_add(unicorn.UC_HOOK_CODE, hook_code)

    uc.reg_write(UC_X86_REG_EDI, prov_ptr)
    uc.reg_write(UC_X86_REG_EBP, ebp)
    uc.reg_write(UC_X86_REG_ESP, esp)

    # Start emulation at 0x004B1E16, stop at 0x004B1FA9
    uc.emu_start(0x004B1E16, 0x004B1FA9, timeout=3000000)

    # Read final vector bounds
    final_end = struct.unpack('<I', uc.mem_read(prov_ptr + 0x388, 4))[0]
    final_count = (final_end - vec_begin) // 4

    return {
        'fired_ids': fired_ids,
        'destroyed_ptrs': destroyed_ptrs,
        'final_count': final_count,
    }

# Test battery
test_cases = [
    [],
    [ProvinceDelayedEventEntry(101, 1)],
    [ProvinceDelayedEventEntry(102, 2)],
    [
        ProvinceDelayedEventEntry(201, 1),
        ProvinceDelayedEventEntry(202, 3),
        ProvinceDelayedEventEntry(203, 1),
        ProvinceDelayedEventEntry(204, 0),
        ProvinceDelayedEventEntry(205, 10),
    ],
    [
        ProvinceDelayedEventEntry(301, 1),
        ProvinceDelayedEventEntry(302, 1),
        ProvinceDelayedEventEntry(303, 1),
    ],
    [
        ProvinceDelayedEventEntry(401, 5),
        ProvinceDelayedEventEntry(402, 8),
        ProvinceDelayedEventEntry(403, 12),
    ],
]

for n_events in (1, 2, 3, 4, 5):
    for delays in ([1]*n_events, [2]*n_events, list(range(1, n_events + 1))):
        events = [
            ProvinceDelayedEventEntry(1000 + i, delays[i])
            for i in range(n_events)
        ]
        test_cases.append(events)

fixture_count = 0
for events in test_cases:
    exp_fired, exp_remaining = process_province_delayed_events_tick(events)
    res = simulate_province_delayed_tick(events)

    assert res['fired_ids'] == exp_fired, (
        f"Fired mismatch: {res['fired_ids']} vs {exp_fired}"
    )
    assert len(res['destroyed_ptrs']) == len(exp_fired), (
        f"Destroyed count mismatch: {len(res['destroyed_ptrs'])} vs {len(exp_fired)}"
    )
    assert res['final_count'] == len(exp_remaining), (
        f"Final count mismatch: {res['final_count']} vs {len(exp_remaining)}"
    )

    fixture_count += 1

out = ROOT / 'evidence/generated/province-event-delayed-tick'
out.mkdir(parents=True, exist_ok=True)
(out / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out / 'emulation.json').write_text(json.dumps({
    'total_fixtures': fixture_count,
    'mismatches': 0,
}, indent=2) + '\n')

ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify')
ledger.record(report, session='province-event-delayed-tick')
ledger.save()

print(f"Province delayed event tick: {len(claims)} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Province delayed event tick emulation: {fixture_count} fixture sets executed, 0 mismatches against province_event_delayed_tick_model.")
