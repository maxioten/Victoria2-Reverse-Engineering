#!/usr/bin/env python3
"""Victoria 2 Address Translator (VA <-> RVA <-> File Offset).

Converts between Ghidra Virtual Address (VA, base 0x400000), Relative Virtual
Address (RVA), and binary File Offset for Victoria 2 (v2game.exe).
"""

import argparse
import os
import sys
from typing import Optional, Tuple, Dict, Any

try:
    import pefile
except ImportError:
    pefile = None


DEFAULT_BINARY = os.path.join(os.path.dirname(__file__), "..", "binaries", "vanilla", "v2game.exe")


class Vic2AddressMap:
    def __init__(self, binary_path: str = DEFAULT_BINARY):
        self.binary_path = os.path.abspath(binary_path)
        self.image_base = 0x400000
        self.sections = []

        if os.path.exists(self.binary_path):
            self._load_pe_sections()
        else:
            # Fallback hardcoded sections for standard v2game.exe (3.04)
            self._set_default_sections()

    def _load_pe_sections(self):
        if pefile is not None:
            try:
                pe = pefile.PE(self.binary_path, fast_load=True)
                self.image_base = pe.OPTIONAL_HEADER.ImageBase
                for s in pe.sections:
                    name = s.Name.decode("latin1", errors="ignore").rstrip("\x00")
                    self.sections.append({
                        "name": name,
                        "va_start": self.image_base + s.VirtualAddress,
                        "va_end": self.image_base + s.VirtualAddress + s.Misc_VirtualSize,
                        "rva_start": s.VirtualAddress,
                        "rva_end": s.VirtualAddress + s.Misc_VirtualSize,
                        "file_start": s.PointerToRawData,
                        "file_end": s.PointerToRawData + s.SizeOfRawData,
                        "raw_size": s.SizeOfRawData,
                        "virtual_size": s.Misc_VirtualSize,
                    })
                pe.close()
                return
            except Exception:
                pass
        self._set_default_sections()

    def _set_default_sections(self):
        self.image_base = 0x400000
        # Grounded fallback for vanilla v2game.exe v3.04
        # SHA-256 62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648
        # Verified via pefile: .text RVA 0x1000 RawPtr 0x400, .rdata RVA 0x88A000 RawPtr 0x888600, etc.
        # Only used when binary is missing or pefile fails; prefer live PE parsing.
        self.sections = [
            {"name": ".text",  "va_start": 0x401000, "va_end": 0x401000 + 0x88811A, "rva_start": 0x1000,   "rva_end": 0x1000 + 0x88811A,   "file_start": 0x400,    "file_end": 0x400 + 0x888200},
            {"name": ".rdata", "va_start": 0xC8A000, "va_end": 0xC8A000 + 0x2673D9, "rva_start": 0x88A000, "rva_end": 0x88A000 + 0x2673D9, "file_start": 0x888600, "file_end": 0x888600 + 0x267400},
            {"name": ".data",  "va_start": 0xEF2000, "va_end": 0xEF2000 + 0x502C24, "rva_start": 0xAF2000, "rva_end": 0xAF2000 + 0x502C24, "file_start": 0xAEFA00, "file_end": 0xAEFA00 + 0x2DA00},
            {"name": ".rsrc",  "va_start": 0x13F5000, "va_end": 0x13F5000 + 0x2E88,  "rva_start": 0xFF5000, "rva_end": 0xFF5000 + 0x2E88,  "file_start": 0xB1D400, "file_end": 0xB1D400 + 0x3000},
            {"name": ".reloc", "va_start": 0x13F8000, "va_end": 0x13F8000 + 0x99556, "rva_start": 0xFF8000, "rva_end": 0xFF8000 + 0x99556, "file_start": 0xB20400, "file_end": 0xB20400 + 0x99600},
        ]

    def from_va(self, va: int) -> Dict[str, Any]:
        rva = va - self.image_base
        for s in self.sections:
            if s["va_start"] <= va < s["va_end"]:
                offset_in_sec = va - s["va_start"]
                file_offset = s["file_start"] + offset_in_sec
                return {
                    "va": hex(va),
                    "rva": hex(rva),
                    "file_offset": hex(file_offset),
                    "section": s["name"],
                    "valid_file_offset": file_offset < s["file_end"],
                }
        return {"va": hex(va), "rva": hex(rva), "file_offset": None, "section": "unknown"}

    def from_rva(self, rva: int) -> Dict[str, Any]:
        va = self.image_base + rva
        return self.from_va(va)

    def from_file_offset(self, file_offset: int) -> Dict[str, Any]:
        for s in self.sections:
            if s["file_start"] <= file_offset < s["file_end"]:
                offset_in_sec = file_offset - s["file_start"]
                va = s["va_start"] + offset_in_sec
                rva = s["rva_start"] + offset_in_sec
                return {
                    "va": hex(va),
                    "rva": hex(rva),
                    "file_offset": hex(file_offset),
                    "section": s["name"],
                }
        return {"va": None, "rva": None, "file_offset": hex(file_offset), "section": "unknown"}

    def read_bytes(self, file_offset: int, length: int = 16) -> Optional[bytes]:
        if not os.path.exists(self.binary_path):
            return None
        with open(self.binary_path, "rb") as f:
            f.seek(file_offset)
            return f.read(length)


def parse_addr(val: str) -> int:
    val = val.strip()
    return int(val, 16) if (val.startswith("0x") or val.startswith("0X") or any(c in "abcdefABCDEF" for c in val)) else int(val)


def main():
    parser = argparse.ArgumentParser(description="Victoria 2 Address Translator (VA / RVA / File Offset)")
    parser.add_argument("address", help="Address to translate (e.g. 0x5c8c9b or 0x1C809B)")
    parser.add_argument("--type", choices=["va", "rva", "file", "auto"], default="auto", help="Address type (default: auto)")
    parser.add_argument("--binary", default=DEFAULT_BINARY, help="Path to v2game.exe")
    parser.add_argument("--bytes", type=int, default=16, help="Number of bytes to inspect at address")
    args = parser.parse_args()

    addr_map = Vic2AddressMap(args.binary)
    addr_val = parse_addr(args.address)

    addr_type = args.type
    if addr_type == "auto":
        if addr_val >= addr_map.image_base:
            addr_type = "va"
        else:
            # Check if likely RVA or file offset
            addr_type = "rva"

    if addr_type == "va":
        res = addr_map.from_va(addr_val)
    elif addr_type == "rva":
        res = addr_map.from_rva(addr_val)
    elif addr_type == "file":
        res = addr_map.from_file_offset(addr_val)
    else:
        res = addr_map.from_va(addr_val)

    print("========================================")
    print(" Victoria 2 Address Map (v2game.exe)")
    print("========================================")
    print(f" Target Binary: {addr_map.binary_path}")
    print(f" Input Type:    {addr_type.upper()}")
    print(f" Input Value:   {args.address}")
    print("----------------------------------------")
    print(f" Ghidra VA:     {res.get('va')}")
    print(f" RVA:           {res.get('rva')}")
    print(f" File Offset:   {res.get('file_offset')}")
    print(f" Section:       {res.get('section')}")

    if res.get("file_offset"):
        fo = int(res["file_offset"], 16)
        raw = addr_map.read_bytes(fo, args.bytes)
        if raw:
            hex_str = " ".join(f"{b:02X}" for b in raw)
            ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw)
            print("----------------------------------------")
            print(f" Bytes ({len(raw)} B): {hex_str}")
            print(f" ASCII:        {ascii_str}")
    print("========================================")


if __name__ == "__main__":
    main()
