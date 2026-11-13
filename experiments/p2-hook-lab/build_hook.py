"""Build freestanding PIC blobs (P2 trampoline + Country_Recalculate SESE prod/bench) and enforce PIC gate."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import capstone
import pefile

LAB = Path(__file__).resolve().parent
ROOT = LAB.parent.parent
COMPILER = ROOT / 'tools/llvm-mingw/llvm-mingw-20261104-msvcrt-ubuntu-22.04-x86_64/bin/i686-w64-mingw32-gcc'
OUT = LAB / 'build'


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_and_gate_blob(
    name: str,
    sources: list[str],
    entry_sym: str,
    required_exports: list[str],
    cfg_sym: str,
    cfg_size: int,
    extra_cflags: list[str],
    hdr_prefix: str,
    hdr_name: str,
    forbid_mnemonics: set[str] | None = None,
    require_mnemonics: set[str] | None = None,
) -> dict:
    assert COMPILER.is_file(), f'Missing compiler: {COMPILER}'
    OUT.mkdir(parents=True, exist_ok=True)
    exe_path = OUT / f'{name}.exe'
    bin_path = OUT / f'{name}.bin'
    hdr_path = OUT / hdr_name
    meta_path = OUT / f'{name}_build.json'

    cmd = [
        str(COMPILER),
        '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
        '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
        '-fno-asynchronous-unwind-tables', '-fno-unwind-tables', '-fno-ident',
        '-fno-jump-tables', '-mno-sse', '-mno-mmx', '-msoft-float', '-nostdlib',
        *extra_cflags,
        f'-Wl,--entry,{entry_sym},--image-base,0x10000000,--disable-dynamicbase,--export-all-symbols',
        *[str(LAB / s) for s in sources],
        '-o', str(exe_path),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr, file=sys.stderr)
        proc.check_returncode()

    pe = pefile.PE(str(exe_path))
    assert pe.FILE_HEADER.Machine == 0x14C, f'Unexpected machine: {hex(pe.FILE_HEADER.Machine)}'

    imports = getattr(pe, 'DIRECTORY_ENTRY_IMPORT', [])
    assert not imports, f'{name} gate failed: expected 0 imports, got {len(imports)}'

    relocs = [
        e for block in getattr(pe, 'DIRECTORY_ENTRY_BASERELOC', [])
        for e in block.entries if e.type != 0
    ]
    assert not relocs, f'{name} gate failed: expected 0 base relocations, got {len(relocs)}'

    exec_sections = [s for s in pe.sections if s.Characteristics & 0x20000000]
    assert len(exec_sections) == 1, f'{name}: expected 1 executable section, got {len(exec_sections)}'
    text_sec = exec_sections[0]
    text_name = text_sec.Name.rstrip(b'\x00').decode(errors='replace')
    assert text_name == '.text', f'{name}: unexpected code section {text_name}'

    other_nonempty = []
    export_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0]
    for s in pe.sections:
        sec_name = s.Name.rstrip(b'\x00').decode(errors='replace')
        if sec_name in ('.text', '.edata', '.buildid'):
            continue
        if sec_name == '.rdata':
            sec_rva = s.VirtualAddress
            sec_end = sec_rva + s.Misc_VirtualSize
            exp_rva = export_dir.VirtualAddress
            exp_end = exp_rva + export_dir.Size
            assert sec_rva <= exp_rva and exp_end <= sec_end, f'{name} .rdata unexpected layout'
            prefix = s.get_data()[:exp_rva - sec_rva]
            assert len(prefix) <= 32 and len(prefix) % 4 == 0, f'{name} .rdata prefix len {len(prefix)}'
            words = struct.unpack(f'<{len(prefix) // 4}I', prefix)
            assert all(w in (0, 0xFFFFFFFF) for w in words), f'{name} .rdata constants {[hex(w) for w in words]}'
            continue
        if s.Misc_VirtualSize > 0 or s.SizeOfRawData > 0:
            other_nonempty.append((sec_name, s.Misc_VirtualSize, s.SizeOfRawData))
    assert not other_nonempty, f'{name} gate failed: non-.text sections {other_nonempty}'

    blob = bytearray(text_sec.get_data()[:text_sec.Misc_VirtualSize])
    assert len(blob) > 0

    exports = {
        sym.name.decode(): sym.address - text_sec.VirtualAddress
        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols if sym.name
    }
    for sym in required_exports:
        assert sym in exports, f'{name}: missing export {sym}; got {list(exports)}'
        assert 0 <= exports[sym] < len(blob), f'{name}: export {sym} outside .text'

    cfg_off = exports[cfg_sym]
    assert blob[cfg_off:cfg_off + cfg_size] == bytes(cfg_size), f'{name}: {cfg_sym} must be zero-initialized'

    # Disassemble executable code in .text (excluding trailing zero config struct if at tail)
    code_end = cfg_off if cfg_off + cfg_size == len(blob) else len(blob)
    text_va_start = pe.OPTIONAL_HEADER.ImageBase + text_sec.VirtualAddress
    text_va_end = text_va_start + len(blob)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    seen_mnemonics = set()
    for ins in md.disasm(bytes(blob[:code_end]), text_va_start):
        seen_mnemonics.add(ins.mnemonic)
        if forbid_mnemonics and ins.mnemonic in forbid_mnemonics:
            raise AssertionError(f'{name}: forbidden instruction {ins.mnemonic} at 0x{ins.address:08X}')
        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0:
                raise AssertionError(f'{name}: absolute memory ref at 0x{ins.address:08X}: {ins.mnemonic} {ins.op_str}')
            if op.type == capstone.x86.X86_OP_IMM:
                imm = op.imm & 0xFFFFFFFF
                if ins.mnemonic in ('call', 'jmp') or ins.mnemonic.startswith('j'):
                    assert text_va_start <= imm < text_va_end, f'{name}: external branch at 0x{ins.address:08X}: {ins.op_str}'
                elif pe.OPTIONAL_HEADER.ImageBase <= imm < pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.SizeOfImage:
                    raise AssertionError(f'{name}: ImageBase-relative imm at 0x{ins.address:08X}: {ins.mnemonic} {ins.op_str}')

    if require_mnemonics:
        missing = require_mnemonics - seen_mnemonics
        assert not missing, f'{name}: missing required instructions {sorted(missing)}'

    bin_path.write_bytes(blob)

    guard = f'{hdr_prefix}_H'
    hex_bytes = ', '.join(f'0x{b:02x}' for b in blob)
    hdr_lines = [
        f'#ifndef {guard}',
        f'#define {guard}',
        '#include <stdint.h>',
        f'#define {hdr_prefix}_SIZE {len(blob)}u',
    ]
    for sym in required_exports:
        hdr_lines.append(f'#define {hdr_prefix}_OFF_{sym.upper()} 0x{exports[sym]:X}u')
    hdr_lines.append(f'static const uint8_t {hdr_prefix}_BLOB[{len(blob)}] = {{ {hex_bytes} }};')
    hdr_lines.append('#endif')
    hdr_lines.append('')
    hdr_path.write_text('\n'.join(hdr_lines))

    meta = {
        'status': 'gate_passed',
        'name': name,
        'compiler': subprocess.check_output([str(COMPILER), '--version'], text=True).splitlines()[0],
        'compiler_command': cmd,
        'sources': {n: sha256_file(LAB / n) for n in ['p2_layout.h', *sources]},
        'exe_sha256': sha256_file(exe_path),
        'blob_sha256': sha256_file(bin_path),
        'blob_bytes': len(blob),
        'imports': 0,
        'base_relocations': 0,
        'sections': [s.Name.rstrip(b'\x00').decode(errors='replace') for s in pe.sections],
        'offsets': {k: exports[k] for k in required_exports},
    }
    meta_path.write_text(json.dumps(meta, indent=2) + '\n')
    return meta


def main() -> None:
    hook_meta = build_and_gate_blob(
        name='hook',
        sources=['hook_blob.c', 'hook.S'],
        entry_sym='_p2_hook_entry',
        required_exports=['p2_hook_entry', 'p2_pic_nop_entry', 'p2_hook_config', 'p2_dispatch'],
        cfg_sym='p2_hook_config',
        cfg_size=32,
        extra_cflags=[],
        hdr_prefix='P2_HOOK_BLOB_DATA',
        hdr_name='hook_blob_data.h',
        forbid_mnemonics={'rdtsc'},
    )
    # Preserve original build.json + hook_blob_data.h macro names expected by v2p2.c / bench.c
    blob = (OUT / 'hook.bin').read_bytes()
    exp = hook_meta['offsets']
    hex_bytes = ', '.join(f'0x{b:02x}' for b in blob)
    (OUT / 'hook_blob_data.h').write_text('\n'.join([
        '#ifndef P2_HOOK_BLOB_DATA_H',
        '#define P2_HOOK_BLOB_DATA_H',
        '#include <stdint.h>',
        f'#define P2_BLOB_SIZE {len(blob)}u',
        f'#define P2_OFF_HOOK_ENTRY 0x{exp["p2_hook_entry"]:X}u',
        f'#define P2_OFF_PIC_NOP_ENTRY 0x{exp["p2_pic_nop_entry"]:X}u',
        f'#define P2_OFF_HOOK_CONFIG 0x{exp["p2_hook_config"]:X}u',
        f'#define P2_OFF_DISPATCH 0x{exp["p2_dispatch"]:X}u',
        f'static const uint8_t P2_HOOK_BLOB[{len(blob)}] = {{ {hex_bytes} }};',
        '#endif',
        '',
    ]))
    (OUT / 'build.json').write_text(json.dumps(hook_meta, indent=2) + '\n')

    cr_prod = build_and_gate_blob(
        name='cr_sese',
        sources=['cr_sese_body.c', 'cr_sese_entry.S'],
        entry_sym='_cr_sese_entry',
        required_exports=['cr_sese_entry', 'cr_sese_config', 'cr_sese_body'],
        cfg_sym='cr_sese_config',
        cfg_size=28,
        extra_cflags=[],
        hdr_prefix='P2_CR_SESE',
        hdr_name='cr_sese_data.h',
        forbid_mnemonics={'rdtsc'},
        require_mnemonics={'prefetcht0'},
    )

    cr_bench = build_and_gate_blob(
        name='cr_sese_bench',
        sources=['cr_sese_body.c', 'cr_sese_entry.S'],
        entry_sym='_cr_sese_entry',
        required_exports=['cr_sese_entry', 'cr_sese_config', 'cr_sese_body'],
        cfg_sym='cr_sese_config',
        cfg_size=28,
        extra_cflags=['-DP2_CR_BENCH_RDTSC=1'],
        hdr_prefix='P2_CR_SESE_BENCH',
        hdr_name='cr_sese_bench_data.h',
        require_mnemonics={'prefetcht0', 'rdtsc'},
    )

    cr_varc_prod = build_and_gate_blob(
        name='cr_sese_varc',
        sources=['cr_sese_body.c', 'cr_sese_entry.S'],
        entry_sym='_cr_sese_entry',
        required_exports=['cr_sese_entry', 'cr_sese_config', 'cr_sese_body'],
        cfg_sym='cr_sese_config',
        cfg_size=28,
        extra_cflags=['-DP2_CR_VARC=1'],
        hdr_prefix='P2_CR_SESE_VARC',
        hdr_name='cr_sese_varc_data.h',
        forbid_mnemonics={'rdtsc', 'prefetcht0'},
        require_mnemonics={'bsf'},
    )

    cr_varc_bench = build_and_gate_blob(
        name='cr_sese_varc_bench',
        sources=['cr_sese_body.c', 'cr_sese_entry.S'],
        entry_sym='_cr_sese_entry',
        required_exports=['cr_sese_entry', 'cr_sese_config', 'cr_sese_body'],
        cfg_sym='cr_sese_config',
        cfg_size=28,
        extra_cflags=['-DP2_CR_VARC=1', '-DP2_CR_BENCH_RDTSC=1'],
        hdr_prefix='P2_CR_SESE_VARC_BENCH',
        hdr_name='cr_sese_varc_bench_data.h',
        forbid_mnemonics={'prefetcht0'},
        require_mnemonics={'rdtsc', 'bsf'},
    )

    summary = [
        {k: m[k] for k in ('status', 'name', 'blob_bytes', 'blob_sha256', 'imports', 'base_relocations', 'sections', 'offsets')}
        for m in (hook_meta, cr_prod, cr_bench, cr_varc_prod, cr_varc_bench)
    ]
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
