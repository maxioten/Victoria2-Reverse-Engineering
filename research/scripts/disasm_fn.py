#!/usr/bin/env python3
"""Desensambla una funcion completa con Capstone usando los limites de functions.csv.

Uso:
    disasm_fn.py <pe> <va-hex> [--csv RUTA] [--out RUTA.asm]

Por que existe: el desensamblado lineal de Rizin se desincroniza en algunas funciones del
binario (aparecen `invalid` y operandos absurdos). Capstone, partiendo del entry exacto y
avanzando instruccion por instruccion, cierra el rango sin huecos; si el ultimo tramo no
coincide con el final declarado por Ghidra, se avisa.

Salida: listado `VA  bytes  mnemonic ops` y un resumen por stdout (instrucciones, saltos
hacia atras, llamadas directas). No modifica el binario.
"""
import argparse
import csv
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

BASE = 0x00400000
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CSV = str(ROOT / "evidence/generated/ghidra-corrected/functions.csv")


def load_text(pe):
    data = open(pe, "rb").read()
    e = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, e + 6)[0]
    opt = struct.unpack_from("<H", data, e + 20)[0]
    sec = e + 24 + opt
    for i in range(nsec):
        o = sec + i * 40
        name = data[o:o + 8].rstrip(b"\0").decode("ascii", "replace")
        vsz, va, rsz, rp = struct.unpack_from("<IIII", data, o + 8)
        if name == ".text":
            return data[rp:rp + rsz], va
    raise SystemExit("no encontre .text")


def bounds(csv_path, va):
    for row in csv.DictReader(open(csv_path, newline="", encoding="utf-8", errors="replace")):
        try:
            s, e = int(row["entry_va"], 16), int(row["end_va"], 16)
        except (KeyError, ValueError):
            continue
        if s <= va < e:
            return s, e, row.get("name", "?")
    return va, None, "?"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pe")
    ap.add_argument("va")
    ap.add_argument("--csv", default=DEFAULT_CSV)
    ap.add_argument("--out")
    a = ap.parse_args()

    va = int(a.va, 16)
    text, text_va = load_text(a.pe)
    start, end, name = bounds(a.csv, va)
    offset = start - BASE - text_va
    if end is None:
        end = start + len(text) - offset
    blob = text[offset:offset + (end - start)]

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    lines, calls, backward = [], [], []
    last = start
    for ins in md.disasm(blob, start):
        lines.append(f"0x{ins.address:08X}  {ins.bytes.hex():<16} {ins.mnemonic} {ins.op_str}")
        if ins.mnemonic == "call" and ins.op_str.startswith("0x"):
            calls.append((ins.address, int(ins.op_str, 16)))
        if ins.mnemonic.startswith("j") and ins.op_str.startswith("0x"):
            t = int(ins.op_str, 16)
            if t < ins.address:
                backward.append((ins.address, t))
        last = ins.address + ins.size

    cerrrado = (last == end)
    out = a.out or str(ROOT / "evidence/generated/ai-job" / f"{name}.capstone.asm")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(f"; {name} 0x{start:08X}..0x{end:08X} ({end-start} bytes)  capstone\n")
        fh.write("\n".join(lines) + "\n")

    print(f"{name}  0x{start:08X}..0x{end:08X}  {end-start} bytes")
    print(f"  instrucciones: {len(lines)}   cierre exacto del rango: {'si' if cerrrado else 'NO'}")
    print(f"  llamadas directas: {len(calls)}   saltos hacia atras: {len(backward)}")
    if calls:
        print("  destinos: " + ", ".join(f"0x{t:08X}" for _, t in calls[:12]))
    print(f"  listado: {out}")
    return 0 if cerrrado else 1


if __name__ == "__main__":
    sys.exit(main())
