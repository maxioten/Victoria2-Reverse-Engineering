#!/usr/bin/env python3
"""Victoria 2 Disassembler Tool.

Disassembles machine code at given VA, RVA, or File Offset from v2game.exe.
Integrates with Capstone for full-fidelity x86 disassembly and cross-references.
"""

import argparse
import os
import sys

from vic2_addr import Vic2AddressMap, parse_addr, DEFAULT_BINARY

try:
    import capstone
    HAVE_CAPSTONE = True
except ImportError:
    HAVE_CAPSTONE = False


def disassemble_bytes(code_bytes: bytes, base_va: int, count: int = 15):
    if HAVE_CAPSTONE:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        md.detail = True
        instructions = list(md.disasm(code_bytes, base_va, count=count))
        for ins in instructions:
            hex_bytes = " ".join(f"{b:02X}" for b in ins.bytes).ljust(20)
            print(f"0x{ins.address:08X} | {hex_bytes} | {ins.mnemonic:<8} {ins.op_str}")
        return len(instructions)
    else:
        # Simple fallback
        print("Note: Capstone not detected, showing raw hex:")
        for i in range(0, len(code_bytes), 16):
            chunk = code_bytes[i:i+16]
            hex_str = " ".join(f"{b:02X}" for b in chunk).ljust(48)
            print(f"0x{base_va + i:08X} | {hex_str}")
        return len(code_bytes)


def main():
    parser = argparse.ArgumentParser(description="Victoria 2 Disassembler (v2game.exe)")
    parser.add_argument("address", help="Address to disassemble (e.g. 0x5c8c9b)")
    parser.add_argument("--type", choices=["va", "rva", "file", "auto"], default="auto", help="Address type")
    parser.add_argument("--count", type=int, default=15, help="Number of instructions to disassemble")
    parser.add_argument("--bytes", type=int, default=128, help="Byte window to read")
    parser.add_argument("--binary", default=DEFAULT_BINARY, help="Path to v2game.exe")
    args = parser.parse_args()

    addr_map = Vic2AddressMap(args.binary)
    addr_val = parse_addr(args.address)

    addr_type = args.type
    if addr_type == "auto":
        addr_type = "va" if addr_val >= addr_map.image_base else "rva"

    if addr_type == "va":
        res = addr_map.from_va(addr_val)
        va = addr_val
    elif addr_type == "rva":
        res = addr_map.from_rva(addr_val)
        va = int(res["va"], 16)
    else:
        res = addr_map.from_file_offset(addr_val)
        va = int(res["va"], 16) if res.get("va") else addr_map.image_base + addr_val

    if not res.get("file_offset"):
        print(f"Error: Address {args.address} cannot be mapped to a file offset in binary.")
        sys.exit(1)

    fo = int(res["file_offset"], 16)
    code = addr_map.read_bytes(fo, args.bytes)
    if not code:
        print(f"Error reading bytes from file offset {hex(fo)} in {args.binary}")
        sys.exit(1)

    print("================================================================================")
    print(f" Disassembly at VA: 0x{va:08X} (RVA: {res.get('rva')}, Offset: {res.get('file_offset')}, Sec: {res.get('section')})")
    print("================================================================================")
    section = res.get("section")
    if section != ".text":
        print(f"WARNING: Section is '{section}', not '.text'. Bytes may be data (e.g. .rdata doubles), not code.")
        print("Output below is a raw decode attempt — do not treat `add [eax],al`-style output as instructions.")
        print("--------------------------------------------------------------------------------")
    disassemble_bytes(code, va, count=args.count)
    print("================================================================================")


if __name__ == "__main__":
    main()
