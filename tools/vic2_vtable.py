#!/usr/bin/env python3
"""Victoria 2 Vtable Inspector.

Inspects, dumps, and disassembles virtual method tables in v2game.exe.
"""

import argparse
import struct
import os
import sys
from typing import List, Dict, Any

from vic2_addr import Vic2AddressMap, parse_addr, DEFAULT_BINARY
from vic2_disasm import disassemble_bytes

DOCUMENTED_VTABLES = {
    "CTechnologyView": {"rva": 0xA17FA4, "slots": 25, "desc": "Technology screen view controller"},
    "CBudgetView":     {"rva": 0xA059F0, "slots": 25, "desc": "Budget screen view controller"},
    "CProductionView": {"rva": 0xA0FECC, "slots": 25, "desc": "Production screen view controller"},
    "CPoliticsView":   {"rva": 0xA0E458, "slots": 25, "desc": "Politics screen view controller"},
    "CDecision":       {"rva": 0xA29B54, "slots": 15, "desc": "Decision evaluation object"},
}


def dump_vtable(addr_map: Vic2AddressMap, name: str, rva: int, num_slots: int = 20, disasm_slot: int = -1):
    res = addr_map.from_rva(rva)
    if not res.get("file_offset"):
        print(f"[-] Vtable {name} RVA {hex(rva)} cannot be resolved to file offset.")
        return

    fo = int(res["file_offset"], 16)
    raw = addr_map.read_bytes(fo, num_slots * 4)
    if not raw or len(raw) < 4:
        print(f"[-] Could not read vtable data at offset {hex(fo)}")
        return

    print("================================================================================")
    print(f" Vtable: {name} (RVA: {hex(rva)}, VA: {res.get('va')}, Offset: {hex(fo)})")
    print("================================================================================")
    print(f"{'Slot':<5} | {'Offset':<8} | {'Target VA':<12} | {'Target RVA':<12} | {'Target Offset':<14}")
    print("-" * 80)

    method_vas = []
    for slot in range(0, len(raw) // 4):
        method_va = struct.unpack("<I", raw[slot*4:(slot+1)*4])[0]
        method_vas.append(method_va)
        m_res = addr_map.from_va(method_va)
        m_rva = m_res.get("rva", "-")
        m_fo = m_res.get("file_offset", "-")
        print(f"{slot:<5} | +0x{slot*4:02X}   | 0x{method_va:08X}   | {str(m_rva):<12} | {str(m_fo):<14}")

    if 0 <= disasm_slot < len(method_vas):
        target_va = method_vas[disasm_slot]
        m_res = addr_map.from_va(target_va)
        if m_res.get("file_offset"):
            t_fo = int(m_res["file_offset"], 16)
            code = addr_map.read_bytes(t_fo, 64)
            print("-" * 80)
            print(f" Disassembly of Slot #{disasm_slot} -> VA: 0x{target_va:08X}:")
            print("-" * 80)
            disassemble_bytes(code, target_va, count=10)

    print("================================================================================")


def main():
    parser = argparse.ArgumentParser(description="Victoria 2 Vtable Inspector")
    parser.add_argument("name_or_addr", nargs="?", default=None, help="Vtable name or RVA/VA (e.g. CTechnologyView or 0xA17FA4)")
    parser.add_argument("--slots", type=int, default=20, help="Number of slots to dump")
    parser.add_argument("--disasm", type=int, default=-1, help="Disassemble method at specified slot index")
    parser.add_argument("--binary", default=DEFAULT_BINARY, help="Path to v2game.exe")
    args = parser.parse_args()

    addr_map = Vic2AddressMap(args.binary)

    if not args.name_or_addr:
        print("================================================================================")
        print(" Victoria 2 Known Vtables")
        print("================================================================================")
        for name, info in DOCUMENTED_VTABLES.items():
            res = addr_map.from_rva(info["rva"])
            print(f" - {name:<18} | RVA: {hex(info['rva']):<10} | VA: {res.get('va'):<10} | {info['desc']}")
        print("================================================================================")
        print("Usage: python3 tools/vic2_vtable.py <name_or_address> [--disasm <slot>]")
        return

    name = args.name_or_addr
    if name in DOCUMENTED_VTABLES:
        info = DOCUMENTED_VTABLES[name]
        dump_vtable(addr_map, name, info["rva"], args.slots, args.disasm)
    else:
        addr = parse_addr(name)
        if addr >= addr_map.image_base:
            addr = addr - addr_map.image_base
        dump_vtable(addr_map, f"Custom_0x{addr:X}", addr, args.slots, args.disasm)


if __name__ == "__main__":
    main()
