"""Intra-region RDTSC microbenchmark for Country_Recalculate SESE [0x00515EA6 -> 0x00516286)."""
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

LAB = Path(__file__).resolve().parent
sys.path.insert(0, str(LAB))
import build_hook  # noqa: E402

ROOT = LAB.parent.parent
CC = ROOT / 'tools/llvm-mingw/llvm-mingw-20261104-msvcrt-ubuntu-22.04-x86_64/bin/i686-w64-mingw32-gcc'
BUILD = LAB / 'build'
WINE_PREFIX = LAB / 'wine-prefix'
RESULTS_JSON = LAB / 'bench_cr_results.json'


def run_cmd(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return proc.stdout


def summarize(vals: list[int]) -> dict:
    s = sorted(vals)
    n = len(s)
    p95_idx = min(n - 1, int(0.95 * (n - 1)))
    return {
        'n': n,
        'min_cycles': s[0],
        'median_cycles': statistics.median(s),
        'p95_cycles': s[p95_idx],
        'mean_cycles': round(statistics.mean(s), 2),
        'max_cycles': s[-1],
    }


def main() -> None:
    BUILD.mkdir(parents=True, exist_ok=True)

    # Ensure build/cr_sese_bench.bin and header exist via build_hook.py
    build_hook.main()

    # Build the no-prefetch RDTSC baseline and Variant (c) + living-prefetch RDTSC blob
    nopf_info = build_hook.build_and_gate_blob(
        name='cr_sese_nopf_bench',
        sources=['cr_sese_body.c', 'cr_sese_entry.S'],
        entry_sym='_cr_sese_entry',
        required_exports=['cr_sese_entry', 'cr_sese_config', 'cr_sese_body'],
        cfg_sym='cr_sese_config',
        cfg_size=28,
        extra_cflags=['-DP2_CR_BENCH_RDTSC=1', '-DP2_CR_NO_PREFETCH=1'],
        hdr_prefix='P2_CR_SESE_NOPF_BENCH',
        hdr_name='cr_sese_nopf_bench_data.h',
        forbid_mnemonics={'prefetcht0'},
        require_mnemonics={'rdtsc'},
    )
    varc_pf_info = build_hook.build_and_gate_blob(
        name='cr_sese_varc_pf_bench',
        sources=['cr_sese_body.c', 'cr_sese_entry.S'],
        entry_sym='_cr_sese_entry',
        required_exports=['cr_sese_entry', 'cr_sese_config', 'cr_sese_body'],
        cfg_sym='cr_sese_config',
        cfg_size=28,
        extra_cflags=['-DP2_CR_VARC=1', '-DP2_CR_VARC_PREFETCH=1', '-DP2_CR_BENCH_RDTSC=1'],
        hdr_prefix='P2_CR_SESE_VARC_PF_BENCH',
        hdr_name='cr_sese_varc_pf_bench_data.h',
        require_mnemonics={'rdtsc', 'bsf', 'prefetcht0'},
    )

    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    nopf_insns = list(cs.disasm((BUILD / 'cr_sese_nopf_bench.bin').read_bytes(), 0))
    vara_insns = list(cs.disasm((BUILD / 'cr_sese_bench.bin').read_bytes(), 0))
    varc_insns = list(cs.disasm((BUILD / 'cr_sese_varc_bench.bin').read_bytes(), 0))
    varcpf_insns = list(cs.disasm((BUILD / 'cr_sese_varc_pf_bench.bin').read_bytes(), 0))
    assert any(i.mnemonic == 'rdtsc' for i in nopf_insns), 'Missing rdtsc in nopf bench blob'
    assert not any(i.mnemonic == 'prefetcht0' for i in nopf_insns), 'Unexpected prefetcht0 in nopf bench blob'
    assert any(i.mnemonic == 'rdtsc' for i in vara_insns), 'Missing rdtsc in var_a bench blob'
    assert any(i.mnemonic == 'prefetcht0' for i in vara_insns), 'Missing prefetcht0 in var_a bench blob'
    assert any(i.mnemonic == 'bsf' for i in varc_insns) and not any(i.mnemonic == 'prefetcht0' for i in varc_insns)
    assert any(i.mnemonic == 'bsf' for i in varcpf_insns) and any(i.mnemonic == 'prefetcht0' for i in varcpf_insns)

    bench_exe = BUILD / 'bench_cr.exe'
    run_cmd([
        str(CC), '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
        f'-I{LAB}', f'-I{BUILD}',
        str(LAB / 'bench_cr.c'), str(LAB / 'bench_cr_asm.S'), '-o', str(bench_exe),
    ])

    env = os.environ.copy()
    env['WINEPREFIX'] = str(WINE_PREFIX)
    env['WINEDEBUG'] = '-all'
    env.pop('WINEARCH', None)
    proc = subprocess.run(['wine', str(bench_exe)], env=env, capture_output=True, text=True, check=True)

    buckets: dict[tuple[str, str], list[int]] = {
        ('cold_clflush', 'nopf'): [],
        ('cold_clflush', 'var_a'): [],
        ('cold_clflush', 'var_c'): [],
        ('cold_clflush', 'var_c_pf'): [],
        ('warm_cached', 'nopf'): [],
        ('warm_cached', 'var_a'): [],
        ('warm_cached', 'var_c'): [],
        ('warm_cached', 'var_c_pf'): [],
    }
    for line in proc.stdout.splitlines():
        parts = line.strip().split()
        if len(parts) == 4 and parts[0] == 'SAMPLE':
            _, mode, variant, cyc_s = parts
            buckets[(mode, variant)].append(int(cyc_s))

    summary = {}
    for mode in ('cold_clflush', 'warm_cached'):
        s_nopf = summarize(buckets[(mode, 'nopf')])
        s_vara = summarize(buckets[(mode, 'var_a')])
        s_varc = summarize(buckets[(mode, 'var_c')])
        s_varcpf = summarize(buckets[(mode, 'var_c_pf')])

        def cmp_vs_nopf(s: dict) -> dict:
            md = s['median_cycles'] - s_nopf['median_cycles']
            pd = s['p95_cycles'] - s_nopf['p95_cycles']
            return {
                'median_delta_cycles': md,
                'median_delta_pct': round(100.0 * md / s_nopf['median_cycles'], 2),
                'p95_delta_cycles': pd,
                'p95_delta_pct': round(100.0 * pd / s_nopf['p95_cycles'], 2),
            }

        summary[mode] = {
            'nopf': s_nopf,
            'var_a_prefetcht0': s_vara,
            'var_c_bitmask': s_varc,
            'var_c_living_prefetcht0': s_varcpf,
            'var_a_vs_nopf': cmp_vs_nopf(s_vara),
            'var_c_vs_nopf': cmp_vs_nopf(s_varc),
            'var_c_pf_vs_nopf': cmp_vs_nopf(s_varcpf),
        }

    out = {
        'benchmark': 'Country_Recalculate SESE [0x00515EA6 -> 0x00516286) intra-region RDTSC',
        'fixture': {
            'total_tags': 220,
            'living_tags': 40,
            'dead_tags': 180,
            'country_stride_bytes': 8192,
            'relation_stride_bytes': 4096,
            'prefetch_dist': 3,
            'warmup_iters': 32,
            'measure_iters': 400,
        },
        'blobs': {
            'nopf_bench_sha256': nopf_info['blob_sha256'],
            'var_a_bench_sha256': json.loads((BUILD / 'cr_sese_bench_build.json').read_text())['blob_sha256'],
            'var_c_bench_sha256': json.loads((BUILD / 'cr_sese_varc_bench_build.json').read_text())['blob_sha256'],
            'var_c_pf_bench_sha256': varc_pf_info['blob_sha256'],
        },
        'results': summary,
    }
    RESULTS_JSON.write_text(json.dumps(out, indent=2) + '\n')
    print(json.dumps(out, indent=2))


if __name__ == '__main__':
    main()
