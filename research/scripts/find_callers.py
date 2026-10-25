#!/usr/bin/env python3
"""Busca quien referencia una VA en un PE32: call rel32, jmp rel32 y punteros absolutos.

Uso:
    find_callers.py <pe> <va-hex> [--range HEX]

- `call rel32` (E8) y `jmp rel32` (E9) cuyo destino calculado sea la VA.
- punteros de 4 bytes little-endian iguales a la VA en secciones de datos
  (`rdata`, `data`, `rdata`), que suelen ser slots de vtable o tablas de dispatch.

Todo se imprime como VA del sitio y la seccion donde cayo. No modifica nada.
"""
import struct
import sys

SECT = ("rdata", "data", "text", "rodata")


def load(pe):
    data = open(pe, "rb").read()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    image_base = struct.unpack_from("<I", data, e_lfanew + 24 + 28)[0]
    sec_off = e_lfanew + 24 + opt_size
    secs = []
    for i in range(nsec):
        off = sec_off + i * 40
        name = data[off:off + 8].rstrip(b"\0").decode("ascii", "replace")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, off + 8)
        secs.append({"name": name, "vsize": vsize, "vaddr": vaddr,
                     "raw": data[rawptr:rawptr + rawsize], "rawptr": rawptr})
    return data, image_base, secs


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    pe = sys.argv[1]
    va = int(sys.argv[2], 16)
    data, image_base, secs = load(pe)
    rva = va - image_base
    print(f"objetivo VA=0x{va:08X}  RVA=0x{rva:06X}  base=0x{image_base:08X}")

    calls = 0
    for s in secs:
        raw = s["raw"]
        name = s["name"]
        if name == ".text":
            for i in range(len(raw) - 5):
                op = raw[i]
                if op not in (0xE8, 0xE9):
                    continue
                rel = struct.unpack_from("<i", raw, i + 1)[0]
                src_rva = s["vaddr"] + i
                if src_rva + 5 + rel == rva:
                    kind = "call" if op == 0xE8 else "jmp"
                    print(f"  {kind}  VA=0x{image_base + src_rva:08X}  (RVA 0x{src_rva:06X})")
                    calls += 1
        else:
            pat = struct.pack("<I", va)
            start = 0
            while True:
                i = raw.find(pat, start)
                if i < 0:
                    break
                if i % 4 == 0:
                    src_rva = s["vaddr"] + i
                    print(f"  ptr   VA=0x{image_base + src_rva:08X}  en {name} (RVA 0x{src_rva:06X})")
                    calls += 1
                start = i + 1
    print(f"total referencias: {calls}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
