"""Build v2p2.dll + bench.exe and run the 5-config empty-hook microbenchmark under an isolated Wine prefix."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

LAB = Path(__file__).resolve().parent
ROOT = LAB.parent.parent
CC = ROOT / 'tools/llvm-mingw/llvm-mingw-20261104-msvcrt-ubuntu-22.04-x86_64/bin/i686-w64-mingw32-gcc'
BUILD = LAB / 'build'
WINE_PREFIX = LAB / 'wine-prefix'


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_cmd(cmd, env=None):
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr, file=sys.stderr)
        proc.check_returncode()
    return proc


def main() -> None:
    BUILD.mkdir(parents=True, exist_ok=True)
    # 1. Ensure PIC hook blob + gate are up-to-date
    run_cmd([sys.executable, str(LAB / 'build_hook.py')])

    # 2. Build persistent TGL plugin v2p2.dll
    v2p2_dll = BUILD / 'v2p2.dll'
    run_cmd([
        str(CC), '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
        '-shared', str(LAB / 'v2p2.c'), str(LAB / 'v2p2_varc_asm.S'),
        '-o', str(v2p2_dll),
        '-lkernel32', f'-Wl,--kill-at,--dynamicbase,--nxcompat,-Map,{BUILD / "v2p2.map"}',
    ])

    # 3. Build 5-config empty-hook microbenchmark bench.exe
    bench_exe = BUILD / 'bench.exe'
    run_cmd([
        str(CC), '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
        str(LAB / 'bench.c'), str(LAB / 'bench_asm.S'),
        '-o', str(bench_exe),
        '-lkernel32',
    ])

    # 4. Run under isolated Wine prefix (never touching ~/.wine or base-game/)
    WINE_PREFIX.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env['WINEPREFIX'] = str(WINE_PREFIX)
    env['WINEDEBUG'] = '-all'
    env.pop('WINEARCH', None)

    proc = run_cmd(['wine', str(bench_exe), '10000000', '20'], env=env)
    bench_data = json.loads(proc.stdout)

    # Enrich with provenance & promotion gate computation
    c_hook_ns = bench_data['derived']['C_hook_ns']
    result = {
        'status': 'measured',
        'wine_version': subprocess.check_output(['wine', '--version'], text=True).strip(),
        'wine_prefix': str(WINE_PREFIX),
        'compiler': subprocess.check_output([str(CC), '--version'], text=True).splitlines()[0],
        'artifacts': {
            'hook_bin_sha256': sha256_file(BUILD / 'hook.bin'),
            'v2p2_dll_sha256': sha256_file(v2p2_dll),
            'bench_exe_sha256': sha256_file(bench_exe),
        },
        'benchmark': bench_data,
        'promotion_gate': {
            'C_hook_ns': c_hook_ns,
            'min_T_orig_ns_for_10pct_overhead': round(c_hook_ns * 10.0, 4),
            'min_daily_savings_ms': 0.25,
            'max_E_vs_C_ratio': 1.10,
            'E4_vs_C_ratio': bench_data['derived']['E4_vs_C_ratio'],
            'E4_vs_C_pass': bench_data['derived']['E4_vs_C_ratio'] <= 1.10,
            'E6_vs_C_ratio': bench_data['derived']['E_vs_C_ratio'],
            'E6_vs_C_pass': bench_data['derived']['E_vs_C_ratio'] <= 1.10,
            'E_vs_C_note': 'Host CPU is 6C/6T i5-8600K (no HT); 4thr stays within core headroom while 6thr saturates 100% of host cores and captures OS preemption.',
        },
    }
    out_path = LAB / 'bench_results.json'
    out_path.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
