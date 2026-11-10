#!/usr/bin/env python3
"""Patch the ENet service timeout load to zero in a copy of v2game.exe.

VA 0x00A618C0: 8B 4B 20   mov ecx, dword ptr [ebx + 0x20]
patched:       33 C9 90   xor ecx, ecx; nop

The original is never modified.  The script verifies the target SHA-256 and the
original bytes, then writes a patched copy and a JSON receipt.
"""
import argparse
import hashlib
import json
import shutil
from pathlib import Path

import pefile

EXPECTED_SHA256 = "62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648"
VA = 0x00A618C0
ORIGINAL = bytes.fromhex("8B4B20")
PATCHED = bytes.fromhex("33C990")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def va_to_offset(pe, va):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    rva = va - image_base
    for section in pe.sections:
        size = max(section.Misc_VirtualSize, section.SizeOfRawData)
        if section.VirtualAddress <= rva < section.VirtualAddress + size:
            delta = rva - section.VirtualAddress
            return section.PointerToRawData + delta
    raise SystemExit(f"VA 0x{va:08X} is not inside a section")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", required=True, help="original v2game.exe")
    ap.add_argument("--output", required=True, help="patched copy to write")
    ap.add_argument("--force", action="store_true", help="overwrite output")
    args = ap.parse_args()

    src = Path(args.input)
    dst = Path(args.output)
    if not src.is_file():
        raise SystemExit(f"missing input: {src}")
    if dst.exists() and not args.force:
        raise SystemExit(f"output exists: {dst} (use --force)")
    original_hash = sha256(src)
    if original_hash != EXPECTED_SHA256:
        raise SystemExit(f"unexpected input SHA-256: {original_hash}")

    pe = pefile.PE(str(src), fast_load=True)
    offset = va_to_offset(pe, VA)
    with open(src, "rb") as f:
        f.seek(offset)
        found = f.read(len(ORIGINAL))
    if found != ORIGINAL:
        raise SystemExit(
            f"unexpected bytes at 0x{VA:08X} (file offset 0x{offset:X}): "
            f"{found.hex()} != {ORIGINAL.hex()}"
        )

    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)
    with open(dst, "r+b") as f:
        f.seek(offset)
        f.write(PATCHED)
    patched_hash = sha256(dst)

    receipt = {
        "experiment": "enet-timeout-zero",
        "va": f"0x{VA:08X}",
        "file_offset": f"0x{offset:X}",
        "original_sha256": original_hash,
        "patched_sha256": patched_hash,
        "original_bytes": ORIGINAL.hex(),
        "patched_bytes": PATCHED.hex(),
        "instruction": "mov ecx,[ebx+0x20] -> xor ecx,ecx; nop",
        "note": "timeout 15 ms -> 0 ms for enet_host_service",
    }
    receipt_path = dst.with_suffix(dst.suffix + ".patch.json")
    receipt_path.write_text(json.dumps(receipt, indent=1) + "\n")
    print(json.dumps(receipt, indent=1))
    print(f"receipt: {receipt_path}")


if __name__ == "__main__":
    main()
