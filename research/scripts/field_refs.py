#!/usr/bin/env python3
"""Cuenta referencias a un campo de estructura `[reg + disp32]` en el .text de un PE32.

Uso:
    field_refs.py <pe> <disp-hex> [--kind byte|dword] [--limit N]

Reconoce las formas x86 mas comunes con desplazamiento de 32 bits y registro base
(sin SIB, es decir `mod=10, rm!=100`):

    byte:  80 /7 (cmp imm8)   88 /r (mov [.] , r8)   8A /r (mov r8, [.])
           C6 /0 (mov imm8)   F6 /0 (test imm8)
    dword: 81 /7 (cmp imm32)  89 /r (mov [.], r32)   8B /r (mov r32, [.])
           C7 /0 (mov imm32)   F7 /0 (test imm32)

Imprime el VA de cada sitio y el mnemónico aproximado. No modifica nada.
Sirve para mapear quien lee y quien escribe un campo antes de atribuirle semantica.
"""
import struct
import sys

BYTE_OPS = {
    0x80: ("cmp  byte [..+disp], imm8", 7),
    0x88: ("mov  byte [..+disp], r8", None),
    0x8A: ("mov  r8, byte [..+disp]", None),
    0xC6: ("mov  byte [..+disp], imm8", 0),
    0xF6: ("test byte [..+disp], imm8", 0),
}
DWORD_OPS = {
    0x81: ("cmp  dword [..+disp], imm32", 7),
    0x89: ("mov  dword [..+disp], r32", None),
    0x8B: ("mov  r32, dword [..+disp]", None),
    0xC7: ("mov  dword [..+disp], imm32", 0),
    0xF7: ("test dword [..+disp], imm32", 0),
}


def load(pe):
    data = open(pe, "rb").read()
    e = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, e + 6)[0]
    opt = struct.unpack_from("<H", data, e + 20)[0]
    image_base = struct.unpack_from("<I", data, e + 24 + 28)[0]
    sec_off = e + 24 + opt
    secs = []
    for i in range(nsec):
        o = sec_off + i * 40
        name = data[o:o + 8].rstrip(b"\0").decode("ascii", "replace")
        vsz, va, rsz, rp = struct.unpack_from("<IIII", data, o + 8)
        secs.append((name, va, data[rp:rp + rsz]))
    return image_base, secs


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    pe = sys.argv[1]
    disp = int(sys.argv[2], 16)
    kind = "byte"
    limit = 40
    for i, a in enumerate(sys.argv):
        if a == "--kind":
            kind = sys.argv[i + 1]
        if a == "--limit":
            limit = int(sys.argv[i + 1])
    table = BYTE_OPS if kind == "byte" else DWORD_OPS
    base, secs = load(pe)
    disp_size = {0: 0, 1: 1, 2: 4}

    hits = []
    for name, sva, blob in secs:
        if name != ".text":
            continue
        for opcode, (mnem, ext) in table.items():
            start = 0
            while True:
                i = blob.find(bytes([opcode]), start)
                if i < 0:
                    break
                start = i + 1
                if i + 2 > len(blob):
                    continue
                modrm = blob[i + 1]
                mod, reg, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7
                if rm == 4:                      # SIB: fuera del alcance de este escaneo
                    continue
                if mod == 3:                     # registro, no memoria
                    continue
                n = disp_size[mod]
                if i + 2 + n > len(blob):
                    continue
                value = int.from_bytes(blob[i + 2:i + 2 + n], "little") if n else 0
                if value != disp:
                    continue
                if ext is not None and reg != ext:
                    continue
                hits.append((sva + i, mnem, reg, mod))
    print(f"campo [reg+0x{disp:X}] ({kind})  sitios: {len(hits)}")
    for va, mnem, reg, mod in hits[:limit]:
        print(f"  0x{base + va:08X}  {mnem}   (mod={mod}, reg field={reg})")
    if len(hits) > limit:
        print(f"  ... {len(hits) - limit} mas")
    return 0


if __name__ == "__main__":
    sys.exit(main())
