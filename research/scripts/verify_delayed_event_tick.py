#!/usr/bin/env python3
"""Verify CCountry::ProcessDelayedEvents (0x0050B5C8..0x0050B696)."""
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
from delayed_event_tick_model import DelayedEventEntry, process_delayed_events_tick

ROOT = Path(__file__).resolve().parents[1]
data = (ROOT.parent / 'base-game/v2game.exe').read_bytes()
digest = hashlib.sha256(data).hexdigest()
assert digest == '62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'

pe = pefile.PE(data=data)
image = pe.get_memory_mapped_image()
base = 0x400000

claims = []

# 1. Instruction claims for delayed event loop in CCountry::DailyUpdate
expected_instructions = (
    (0x0050B5C8, 3, 'mov', 'eax, dword ptr [ebx + 0x68]'),
    (0x0050B5CB, 3, 'mov', 'dword ptr [ebp - 0x30], eax'),
    (0x0050B5CE, 3, 'mov', 'eax, dword ptr [ebp - 0x30]'),
    (0x0050B5D1, 3, 'cmp', 'eax, dword ptr [ebx + 0x68]'),
    (0x0050B5D4, 6, 'jb', '0x50b663'),
    (0x0050B5DA, 3, 'cmp', 'eax, dword ptr [ebx + 0x6c]'),
    (0x0050B5DD, 6, 'jae', '0x50b663'),
    (0x0050B5E3, 2, 'mov', 'ecx, eax'),
    (0x0050B5E5, 2, 'mov', 'edi, dword ptr [ecx]'),
    (0x0050B5E7, 3, 'add', 'ecx, 4'),
    (0x0050B5EA, 2, 'mov', 'eax, edi'),
    (0x0050B5EC, 3, 'mov', 'dword ptr [ebp - 0x30], ecx'),
    (0x0050B5EF, 5, 'call', '0x8a58c0'),
    (0x0050B5F4, 2, 'test', 'al, al'),
    (0x0050B5F6, 2, 'jne', '0x50b63c'),
    (0x0050B5FD, 5, 'call', '0xaae9af'),
    (0x0050B63C, 3, 'dec', 'dword ptr [edi + 0x54]'),
    (0x0050B63F, 4, 'cmp', 'dword ptr [edi + 0x54], 0'),
    (0x0050B643, 2, 'jg', '0x50b5ce'),
    (0x0050B645, 3, 'mov', 'edx, dword ptr [edi + 8]'),
    (0x0050B650, 5, 'call', '0x8a6620'),
    (0x0050B65C, 5, 'call', '0x8a8120'),
    (0x0050B663, 3, 'mov', 'esi, dword ptr [ebp - 0x5c]'),
    (0x0050B678, 3, 'lea', 'edx, [ebp + 8]'),
    (0x0050B67B, 3, 'lea', 'eax, [ebx + 0x68]'),
    (0x0050B67E, 5, 'call', '0x4be200'),
    (0x0050B68B, 5, 'call', '0x8601b0'),
)

for address, length, mnemonic, operand in expected_instructions:
    claims.append({
        'id': f'delayed_tick_ins_{address:x}', 'kind': 'instructions', 'space': 'rva',
        'offset': hex(address - base), 'base': hex(address), 'arch': 'x86',
        'length': length, 'mnemonics': [mnemonic], 'operands': [operand]
    })

verifier = Verifier(data)
report = verifier.verify_all([Claim.from_dict(c) for c in claims])
assert all(r['verdict'] == 'VERIFIED' for r in report['results']), [
    r for r in report['results'] if r['verdict'] != 'VERIFIED'
]

# Negative controls
wrong = dict(claims[0], id='negative_control', operands=['eax, dword ptr [ebx + 0x60]'])
dependent = dict(claims[1], id='negative_dependent', depends_on=['negative_control'])
controls = verifier.verify_all([Claim.from_dict(wrong), Claim.from_dict(dependent)])
assert [r['verdict'] for r in controls['results']] == ['REFUTED', 'INVALIDATED']

# 2. Unicorn dynamic emulation of 0x0050B5C8..0x0050B693
def simulate_delayed_tick(events):
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    uc.mem_map(0x400000, 0x1100000, unicorn.UC_PROT_ALL)
    uc.mem_write(0x400000, image)

    # Map zero-page for safe SEH / FS reads
    uc.mem_map(0, 0x1000, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
    # Stack
    stack_base = 0x200000
    stack_size = 0x10000
    uc.mem_map(stack_base, stack_size, unicorn.UC_PROT_ALL)
    ebp = stack_base + stack_size - 0x200
    esp = ebp - 0x80

    # Heap structures
    heap_base = 0x1600000
    uc.mem_map(heap_base, 0x20000, unicorn.UC_PROT_ALL)
    heap_alloc_cur = heap_base + 0x10000

    # Country instance at heap_base
    country_ptr = heap_base + 0x100
    # Vector buffer
    vec_buf = heap_base + 0x400
    event_obj_ptrs = []

    for i, ev in enumerate(events):
        entry_ptr = heap_base + 0x800 + i * 0x100
        # CDelayedEvent layout:
        # +0: vtable, +4: type, +8: event_ptr, +0xC: payload, +0x54: delay
        uc.mem_write(entry_ptr + 0x00, struct.pack('<I', 0x00E2C858))
        uc.mem_write(entry_ptr + 0x04, struct.pack('<I', 0x18D))
        uc.mem_write(entry_ptr + 0x08, struct.pack('<I', ev.event_id))  # use event_id as ptr
        uc.mem_write(entry_ptr + 0x54, struct.pack('<i', ev.delay))
        event_obj_ptrs.append(entry_ptr)
        uc.mem_write(vec_buf + i * 4, struct.pack('<I', entry_ptr))

    vec_begin = vec_buf
    vec_end = vec_buf + len(events) * 4
    vec_cap = vec_end

    uc.mem_write(country_ptr + 0x68, struct.pack('<III', vec_begin, vec_end, vec_cap))

    # Initialize ebp frame locals
    # [ebp - 0x54] = list counter (0)
    # [ebp - 0x58] = list tail (0)
    # [ebp - 0x5c] = list head (0)
    uc.mem_write(ebp - 0x54, struct.pack('<III', 0, 0, 0))
    uc.mem_write(ebp - 0x30, struct.pack('<I', 0))

    fired_ids = []
    erased_ids = []

    # Map validity lookups
    validity_map = {event_obj_ptrs[i]: events[i].is_valid for i in range(len(events))}

    # Install stubs
    # 0x008A58C0: check validity from validity_map
    def hook_code(uc, address, size, user_data):
        nonlocal heap_alloc_cur
        if address == 0x008A58C0:
            # eax = CDelayedEvent*
            eax_val = uc.reg_read(UC_X86_REG_EAX)
            is_valid = validity_map.get(eax_val, True)
            uc.reg_write(UC_X86_REG_EAX, 1 if is_valid else 0)
            # simulate ret
            esp_val = uc.reg_read(UC_X86_REG_ESP)
            ret_target = struct.unpack('<I', uc.mem_read(esp_val, 4))[0]
            uc.reg_write(UC_X86_REG_ESP, esp_val + 4)
            uc.reg_write(unicorn.x86_const.UC_X86_REG_EIP, ret_target)
        elif address == 0x00AAE9AF:  # malloc(0x10) for list node
            # allocate 0x10
            alloc_ptr = heap_alloc_cur
            heap_alloc_cur += 0x10
            uc.reg_write(UC_X86_REG_EAX, alloc_ptr)
            esp_val = uc.reg_read(UC_X86_REG_ESP)
            ret_target = struct.unpack('<I', uc.mem_read(esp_val, 4))[0]
            uc.reg_write(UC_X86_REG_ESP, esp_val + 4)
            uc.reg_write(unicorn.x86_const.UC_X86_REG_EIP, ret_target)
        elif address == 0x008A6620:  # context init: ret
            esp_val = uc.reg_read(UC_X86_REG_ESP)
            ret_target = struct.unpack('<I', uc.mem_read(esp_val, 4))[0]
            uc.reg_write(UC_X86_REG_ESP, esp_val + 4)
            uc.reg_write(unicorn.x86_const.UC_X86_REG_EIP, ret_target)
        elif address == 0x008A8120:  # Event_Fire(ecx = event_id, arg = context)
            ev_id = uc.reg_read(UC_X86_REG_ECX)
            fired_ids.append(ev_id)
            esp_val = uc.reg_read(UC_X86_REG_ESP)
            # stub ret 4
            ret_target = struct.unpack('<I', uc.mem_read(esp_val, 4))[0]
            uc.reg_write(UC_X86_REG_ESP, esp_val + 8)
            uc.reg_write(unicorn.x86_const.UC_X86_REG_EIP, ret_target)
        elif address == 0x004BE200:  # vector erase
            # edx = &[ebp + 8] = pointer to event_ptr
            edx_val = uc.reg_read(UC_X86_REG_EDX)
            erased_ptr = struct.unpack('<I', uc.mem_read(edx_val, 4))[0]
            # find which event_id
            for i, p in enumerate(event_obj_ptrs):
                if p == erased_ptr:
                    erased_ids.append(events[i].event_id)
            # simulate ret
            esp_val = uc.reg_read(UC_X86_REG_ESP)
            ret_target = struct.unpack('<I', uc.mem_read(esp_val, 4))[0]
            uc.reg_write(UC_X86_REG_ESP, esp_val + 4)
            uc.reg_write(unicorn.x86_const.UC_X86_REG_EIP, ret_target)
        elif address == 0x008601B0:  # list dtor: ret 4
            esp_val = uc.reg_read(UC_X86_REG_ESP)
            ret_target = struct.unpack('<I', uc.mem_read(esp_val, 4))[0]
            uc.reg_write(UC_X86_REG_ESP, esp_val + 8)
            uc.reg_write(unicorn.x86_const.UC_X86_REG_EIP, ret_target)

    hook = uc.hook_add(unicorn.UC_HOOK_CODE, hook_code)

    uc.reg_write(UC_X86_REG_EBX, country_ptr)
    uc.reg_write(UC_X86_REG_EBP, ebp)
    uc.reg_write(UC_X86_REG_ESP, esp)

    # Execute from 0x0050B5C8 to 0x0050B693
    uc.emu_start(0x0050B5C8, 0x0050B693, timeout=3000000)

    # Read back delays
    remaining_delays = []
    for i, p in enumerate(event_obj_ptrs):
        d = struct.unpack('<i', uc.mem_read(p + 0x54, 4))[0]
        remaining_delays.append(d)

    return {
        'fired_ids': fired_ids,
        'erased_ids': erased_ids,
        'remaining_delays': remaining_delays,
    }

# Test battery
test_cases = [
    # 1. Empty vector
    [],
    # 2. Single event, delay = 1 -> fires and erased
    [DelayedEventEntry(101, 1, True)],
    # 3. Single event, delay = 2 -> delay decrements to 1, does NOT fire, NOT erased
    [DelayedEventEntry(102, 2, True)],
    # 4. Single event, invalid -> NOT fired, erased
    [DelayedEventEntry(103, 5, False)],
    # 5. Multiple mixed events
    [
        DelayedEventEntry(201, 1, True),
        DelayedEventEntry(202, 3, True),
        DelayedEventEntry(203, 1, False),
        DelayedEventEntry(204, 0, True),  # delay 0: dec to -1, fires!
        DelayedEventEntry(205, 10, True),
    ],
    # 6. All firing
    [
        DelayedEventEntry(301, 1, True),
        DelayedEventEntry(302, 1, True),
        DelayedEventEntry(303, 1, True),
    ],
    # 7. None firing
    [
        DelayedEventEntry(401, 5, True),
        DelayedEventEntry(402, 8, True),
        DelayedEventEntry(403, 12, True),
    ],
]

# Systematic fixtures
for n_events in (1, 2, 3, 4, 5):
    for delays in ([1]*n_events, [2]*n_events, list(range(1, n_events + 1))):
        for all_valid in (True, False):
            events = [
                DelayedEventEntry(1000 + i, delays[i], all_valid or (i % 2 == 0))
                for i in range(n_events)
            ]
            test_cases.append(events)

fixture_count = 0
for events in test_cases:
    exp_fired, exp_discarded, exp_remaining = process_delayed_events_tick(events)
    res = simulate_delayed_tick(events)

    assert res['fired_ids'] == exp_fired, (
        f"Fired mismatch: {res['fired_ids']} vs {exp_fired}"
    )
    expected_erased = set(exp_fired) | set(exp_discarded)
    assert set(res['erased_ids']) == expected_erased, (
        f"Erased mismatch: {set(res['erased_ids'])} vs {expected_erased}"
    )

    # Check delays
    for i, ev in enumerate(events):
        if ev.is_valid:
            assert res['remaining_delays'][i] == ev.delay - 1

    fixture_count += 1

out = ROOT / 'evidence/generated/event-delayed-tick'
out.mkdir(parents=True, exist_ok=True)
(out / 'claims.json').write_text(json.dumps(claims, indent=2) + '\n')
(out / 'reverify.json').write_text(json.dumps(report, indent=2) + '\n')
(out / 'negative-controls.json').write_text(json.dumps(controls, indent=2) + '\n')
(out / 'emulation.json').write_text(json.dumps({
    'total_fixtures': fixture_count,
    'mismatches': 0,
}, indent=2) + '\n')

ledger = Ledger.for_bytes(data, directory=ROOT / '.reverify')
ledger.record(report, session='event-delayed-tick')
ledger.save()

print(f"Delayed event tick: {len(claims)} reverify checks verified; wrong-target control REFUTED; dependent INVALIDATED.")
print(f"Delayed event tick emulation: {fixture_count} fixture sets executed, 0 mismatches against delayed_event_tick_model.")
