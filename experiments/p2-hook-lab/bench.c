#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "p2_layout.h"
#include "build/hook_blob_data.h"

extern void __stdcall dummy_target_ret4(uint32_t x);
extern uint32_t __cdecl bench_run_direct_batch(uint32_t count, uint32_t seed);
extern uint8_t bench_callsite_direct[];
extern uint32_t __cdecl bench_run_vtable_batch(uint32_t count, void *obj_with_vtbl, uint32_t seed);
extern uint32_t __cdecl bench_run_threaded_batch(uint32_t count, uint32_t seed);
extern uint8_t bench_callsite_threaded[];

static volatile uint32_t g_sink = 0;

static int __cdecl empty_c_handler_fallback(P2SavedState *regs, P2FxSave *fx, const P2HookConfig *cfg) {
    (void)regs;
    (void)fx;
    (void)cfg;
    return P2_ACT_FALLBACK;
}

static int __cdecl empty_c_handler_handled(P2SavedState *regs, P2FxSave *fx, const P2HookConfig *cfg) {
    (void)regs;
    (void)fx;
    (void)cfg;
    return P2_ACT_HANDLED;
}

static inline uint64_t read_tsc_serialized(void) {
    uint32_t lo, hi, aux;
    __asm__ volatile ("lfence\n\trdtscp" : "=a"(lo), "=d"(hi), "=c"(aux) :: "memory");
    return ((uint64_t)hi << 32) | lo;
}

static uint8_t *alloc_sealed_blob(
    uint32_t original_target,
    uint32_t handler_fn,
    uint32_t mode,
    uint32_t arg_bytes,
    uint32_t flags
) {
    uint8_t *page = (uint8_t *)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!page) {
        fprintf(stderr, "VirtualAlloc failed\n");
        exit(1);
    }
    memcpy(page, P2_HOOK_BLOB, P2_BLOB_SIZE);

    P2HookConfig cfg;
    cfg.original_target = original_target;
    cfg.handler_fn = handler_fn;
    cfg.mode = mode;
    cfg.arg_bytes = arg_bytes;
    cfg.flags = flags;
    cfg.tls_slot = 0xFFFFFFFFu;
    cfg.user_data = 0u;
    cfg.reserved = 0u;
    memcpy(page + P2_OFF_HOOK_CONFIG, &cfg, sizeof(cfg));

    DWORD old_prot = 0;
    if (!VirtualProtect(page, 4096, PAGE_EXECUTE_READ, &old_prot)) {
        fprintf(stderr, "VirtualProtect(PAGE_EXECUTE_READ) failed\n");
        exit(1);
    }
    FlushInstructionCache(GetCurrentProcess(), page, P2_BLOB_SIZE);
    return page;
}

static void patch_rel32_call(uint8_t *site, void *target) {
    if (site[0] != 0xE8) {
        fprintf(stderr, "Expected 0xE8 at callsite\n");
        exit(1);
    }
    DWORD old_prot = 0;
    if (!VirtualProtect(site, 5, PAGE_EXECUTE_READWRITE, &old_prot)) {
        fprintf(stderr, "VirtualProtect callsite failed\n");
        exit(1);
    }
    int32_t rel = (int32_t)((uintptr_t)target - (uintptr_t)(site + 5));
    memcpy(site + 1, &rel, sizeof(rel));
    DWORD dummy = 0;
    VirtualProtect(site, 5, old_prot, &dummy);
    FlushInstructionCache(GetCurrentProcess(), site, 5);
}

static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    return (da > db) - (da < db);
}

typedef struct BatchStats {
    double median_cycles;
    double p95_cycles;
    double median_ns;
    double p95_ns;
} BatchStats;

static BatchStats summarize(double *cycles, double *ns, int m) {
    qsort(cycles, (size_t)m, sizeof(double), cmp_double);
    qsort(ns, (size_t)m, sizeof(double), cmp_double);
    BatchStats s;
    if (m % 2 == 1) {
        s.median_cycles = cycles[m / 2];
        s.median_ns = ns[m / 2];
    } else {
        s.median_cycles = 0.5 * (cycles[m / 2 - 1] + cycles[m / 2]);
        s.median_ns = 0.5 * (ns[m / 2 - 1] + ns[m / 2]);
    }
    int p95_idx = (int)(0.95 * (double)(m - 1) + 0.5);
    if (p95_idx >= m) p95_idx = m - 1;
    s.p95_cycles = cycles[p95_idx];
    s.p95_ns = ns[p95_idx];
    return s;
}

typedef struct WorkerArgs {
    HANDLE start_event;
    uint32_t warmup;
    uint32_t n_calls;
    uint32_t batches;
    uint32_t seed;
    double qpc_freq;
    double *cycles_out;
    double *ns_out;
} WorkerArgs;

static DWORD WINAPI worker_proc(LPVOID param) {
    WorkerArgs *w = (WorkerArgs *)param;
    g_sink ^= bench_run_threaded_batch(w->warmup, w->seed);
    WaitForSingleObject(w->start_event, INFINITE);

    uint32_t acc = w->seed;
    for (uint32_t b = 0; b < w->batches; ++b) {
        LARGE_INTEGER q0, q1;
        QueryPerformanceCounter(&q0);
        uint64_t t0 = read_tsc_serialized();
        acc = bench_run_threaded_batch(w->n_calls, acc);
        uint64_t t1 = read_tsc_serialized();
        QueryPerformanceCounter(&q1);
        w->cycles_out[b] = (double)(t1 - t0) / (double)w->n_calls;
        w->ns_out[b] = ((double)(q1.QuadPart - q0.QuadPart) * 1e9) / (w->qpc_freq * (double)w->n_calls);
    }
    g_sink ^= acc;
    return 0;
}

int main(int argc, char **argv) {
    uint32_t warmup = 1000000u;
    uint32_t n_calls = 10000000u;
    int batches = 20;
    if (argc >= 2) n_calls = (uint32_t)strtoul(argv[1], NULL, 10);
    if (argc >= 3) batches = atoi(argv[2]);
    if (batches < 5) batches = 5;

    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    SetThreadAffinityMask(GetCurrentThread(), 1);

    LARGE_INTEGER qpc_freq_li;
    QueryPerformanceFrequency(&qpc_freq_li);
    double qpc_freq = (double)qpc_freq_li.QuadPart;

    /* Calibrate TSC frequency over 250 ms */
    LARGE_INTEGER cq0, cq1;
    QueryPerformanceCounter(&cq0);
    uint64_t ct0 = read_tsc_serialized();
    Sleep(250);
    uint64_t ct1 = read_tsc_serialized();
    QueryPerformanceCounter(&cq1);
    double cal_sec = (double)(cq1.QuadPart - cq0.QuadPart) / qpc_freq;
    double tsc_ghz = ((double)(ct1 - ct0) / cal_sec) / 1e9;

    double *cyc = (double *)calloc((size_t)batches, sizeof(double));
    double *ns = (double *)calloc((size_t)batches, sizeof(double));

    /* A: baseline_direct */
    g_sink ^= bench_run_direct_batch(warmup, 1u);
    uint32_t acc = 1u;
    for (int b = 0; b < batches; ++b) {
        LARGE_INTEGER q0, q1;
        QueryPerformanceCounter(&q0);
        uint64_t t0 = read_tsc_serialized();
        acc = bench_run_direct_batch(n_calls, acc);
        uint64_t t1 = read_tsc_serialized();
        QueryPerformanceCounter(&q1);
        cyc[b] = (double)(t1 - t0) / (double)n_calls;
        ns[b] = ((double)(q1.QuadPart - q0.QuadPart) * 1e9) / (qpc_freq * (double)n_calls);
    }
    g_sink ^= acc;
    BatchStats stat_A = summarize(cyc, ns, batches);

    /* B: pic_nop_trampoline */
    uint8_t *blob_B = alloc_sealed_blob(
        (uint32_t)(uintptr_t)&dummy_target_ret4, 0u, P2_MODE_PROD, 4u, 0u
    );
    patch_rel32_call(bench_callsite_direct, blob_B + P2_OFF_PIC_NOP_ENTRY);
    g_sink ^= bench_run_direct_batch(warmup, 1u);
    for (int b = 0; b < batches; ++b) {
        LARGE_INTEGER q0, q1;
        QueryPerformanceCounter(&q0);
        uint64_t t0 = read_tsc_serialized();
        acc = bench_run_direct_batch(n_calls, acc);
        uint64_t t1 = read_tsc_serialized();
        QueryPerformanceCounter(&q1);
        cyc[b] = (double)(t1 - t0) / (double)n_calls;
        ns[b] = ((double)(q1.QuadPart - q0.QuadPart) * 1e9) / (qpc_freq * (double)n_calls);
    }
    g_sink ^= acc;
    BatchStats stat_B = summarize(cyc, ns, batches);

    /* C: pic_empty_c_handler (fallback path -> original dummy_target_ret4) */
    uint8_t *blob_C = alloc_sealed_blob(
        (uint32_t)(uintptr_t)&dummy_target_ret4,
        (uint32_t)(uintptr_t)&empty_c_handler_fallback,
        P2_MODE_PROD, 4u, 0u
    );
    patch_rel32_call(bench_callsite_direct, blob_C + P2_OFF_HOOK_ENTRY);
    g_sink ^= bench_run_direct_batch(warmup, 1u);
    for (int b = 0; b < batches; ++b) {
        LARGE_INTEGER q0, q1;
        QueryPerformanceCounter(&q0);
        uint64_t t0 = read_tsc_serialized();
        acc = bench_run_direct_batch(n_calls, acc);
        uint64_t t1 = read_tsc_serialized();
        QueryPerformanceCounter(&q1);
        cyc[b] = (double)(t1 - t0) / (double)n_calls;
        ns[b] = ((double)(q1.QuadPart - q0.QuadPart) * 1e9) / (qpc_freq * (double)n_calls);
    }
    g_sink ^= acc;
    BatchStats stat_C = summarize(cyc, ns, batches);

    /* C_handled: pic_empty_c_handler returning P2_ACT_HANDLED (prod replacement epilogue) */
    uint8_t *blob_Ch = alloc_sealed_blob(
        (uint32_t)(uintptr_t)&dummy_target_ret4,
        (uint32_t)(uintptr_t)&empty_c_handler_handled,
        P2_MODE_PROD, 4u, 0u
    );
    patch_rel32_call(bench_callsite_direct, blob_Ch + P2_OFF_HOOK_ENTRY);
    g_sink ^= bench_run_direct_batch(warmup, 1u);
    for (int b = 0; b < batches; ++b) {
        LARGE_INTEGER q0, q1;
        QueryPerformanceCounter(&q0);
        uint64_t t0 = read_tsc_serialized();
        acc = bench_run_direct_batch(n_calls, acc);
        uint64_t t1 = read_tsc_serialized();
        QueryPerformanceCounter(&q1);
        cyc[b] = (double)(t1 - t0) / (double)n_calls;
        ns[b] = ((double)(q1.QuadPart - q0.QuadPart) * 1e9) / (qpc_freq * (double)n_calls);
    }
    g_sink ^= acc;
    BatchStats stat_Ch = summarize(cyc, ns, batches);

    /* D_base + D: vtable_empty_handler */
    void *vtbl[1] = { (void *)&dummy_target_ret4 };
    void *obj[1] = { (void *)vtbl };
    g_sink ^= bench_run_vtable_batch(warmup, obj, 1u);
    for (int b = 0; b < batches; ++b) {
        LARGE_INTEGER q0, q1;
        QueryPerformanceCounter(&q0);
        uint64_t t0 = read_tsc_serialized();
        acc = bench_run_vtable_batch(n_calls, obj, acc);
        uint64_t t1 = read_tsc_serialized();
        QueryPerformanceCounter(&q1);
        cyc[b] = (double)(t1 - t0) / (double)n_calls;
        ns[b] = ((double)(q1.QuadPart - q0.QuadPart) * 1e9) / (qpc_freq * (double)n_calls);
    }
    g_sink ^= acc;
    BatchStats stat_Dbase = summarize(cyc, ns, batches);

    uint8_t *blob_D = alloc_sealed_blob(
        (uint32_t)(uintptr_t)&dummy_target_ret4,
        (uint32_t)(uintptr_t)&empty_c_handler_fallback,
        P2_MODE_PROD, 4u, 0u
    );
    vtbl[0] = (void *)(blob_D + P2_OFF_HOOK_ENTRY);
    g_sink ^= bench_run_vtable_batch(warmup, obj, 1u);
    for (int b = 0; b < batches; ++b) {
        LARGE_INTEGER q0, q1;
        QueryPerformanceCounter(&q0);
        uint64_t t0 = read_tsc_serialized();
        acc = bench_run_vtable_batch(n_calls, obj, acc);
        uint64_t t1 = read_tsc_serialized();
        QueryPerformanceCounter(&q1);
        cyc[b] = (double)(t1 - t0) / (double)n_calls;
        ns[b] = ((double)(q1.QuadPart - q0.QuadPart) * 1e9) / (qpc_freq * (double)n_calls);
    }
    g_sink ^= acc;
    BatchStats stat_D = summarize(cyc, ns, batches);

    /* Helper-like block: run E_4thr and E_6thr on the same sealed PIC blob */
    enum { MAX_E_THREADS = 6 };
    uint8_t *blob_E = alloc_sealed_blob(
        (uint32_t)(uintptr_t)&dummy_target_ret4,
        (uint32_t)(uintptr_t)&empty_c_handler_fallback,
        P2_MODE_PROD, 4u, 0u
    );
    patch_rel32_call(bench_callsite_threaded, blob_E + P2_OFF_HOOK_ENTRY);

    BatchStats stat_E4 = {0};
    BatchStats stat_E6 = {0};
    const int e_counts[2] = { 4, 6 };
    BatchStats *e_outs[2] = { &stat_E4, &stat_E6 };
    for (int cfg_idx = 0; cfg_idx < 2; ++cfg_idx) {
        int nth = e_counts[cfg_idx];
        HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
        HANDLE threads[MAX_E_THREADS];
        WorkerArgs wargs[MAX_E_THREADS];
        double *all_cyc_E = (double *)calloc((size_t)(nth * batches), sizeof(double));
        double *all_ns_E = (double *)calloc((size_t)(nth * batches), sizeof(double));
        for (int t = 0; t < nth; ++t) {
            wargs[t].start_event = ev;
            wargs[t].warmup = warmup;
            wargs[t].n_calls = n_calls;
            wargs[t].batches = (uint32_t)batches;
            wargs[t].seed = (uint32_t)(t + 1);
            wargs[t].qpc_freq = qpc_freq;
            wargs[t].cycles_out = &all_cyc_E[t * batches];
            wargs[t].ns_out = &all_ns_E[t * batches];
            threads[t] = CreateThread(NULL, 0, worker_proc, &wargs[t], 0, NULL);
        }
        Sleep(50);
        SetEvent(ev);
        WaitForMultipleObjects((DWORD)nth, threads, TRUE, INFINITE);
        for (int t = 0; t < nth; ++t) {
            CloseHandle(threads[t]);
        }
        CloseHandle(ev);
        *e_outs[cfg_idx] = summarize(all_cyc_E, all_ns_E, nth * batches);
        free(all_cyc_E);
        free(all_ns_E);
    }

    printf("{\n");
    printf("  \"warmup\": %u,\n", warmup);
    printf("  \"calls_per_batch\": %u,\n", n_calls);
    printf("  \"batches\": %d,\n", batches);
    printf("  \"threads_E\": 6,\n");
    printf("  \"qpc_freq_hz\": %.0f,\n", qpc_freq);
    printf("  \"tsc_ghz\": %.6f,\n", tsc_ghz);
    printf("  \"configs\": {\n");
    printf("    \"A_baseline_direct\": {\"median_cycles\": %.4f, \"p95_cycles\": %.4f, \"median_ns\": %.4f, \"p95_ns\": %.4f},\n",
           stat_A.median_cycles, stat_A.p95_cycles, stat_A.median_ns, stat_A.p95_ns);
    printf("    \"B_pic_nop_trampoline\": {\"median_cycles\": %.4f, \"p95_cycles\": %.4f, \"median_ns\": %.4f, \"p95_ns\": %.4f},\n",
           stat_B.median_cycles, stat_B.p95_cycles, stat_B.median_ns, stat_B.p95_ns);
    printf("    \"C_pic_empty_c_handler\": {\"median_cycles\": %.4f, \"p95_cycles\": %.4f, \"median_ns\": %.4f, \"p95_ns\": %.4f},\n",
           stat_C.median_cycles, stat_C.p95_cycles, stat_C.median_ns, stat_C.p95_ns);
    printf("    \"C_handled_empty_c_handler\": {\"median_cycles\": %.4f, \"p95_cycles\": %.4f, \"median_ns\": %.4f, \"p95_ns\": %.4f},\n",
           stat_Ch.median_cycles, stat_Ch.p95_cycles, stat_Ch.median_ns, stat_Ch.p95_ns);
    printf("    \"D_baseline_vtable\": {\"median_cycles\": %.4f, \"p95_cycles\": %.4f, \"median_ns\": %.4f, \"p95_ns\": %.4f},\n",
           stat_Dbase.median_cycles, stat_Dbase.p95_cycles, stat_Dbase.median_ns, stat_Dbase.p95_ns);
    printf("    \"D_vtable_empty_handler\": {\"median_cycles\": %.4f, \"p95_cycles\": %.4f, \"median_ns\": %.4f, \"p95_ns\": %.4f},\n",
           stat_D.median_cycles, stat_D.p95_cycles, stat_D.median_ns, stat_D.p95_ns);
    printf("    \"E_tbb_contended_4thr\": {\"median_cycles\": %.4f, \"p95_cycles\": %.4f, \"median_ns\": %.4f, \"p95_ns\": %.4f},\n",
           stat_E4.median_cycles, stat_E4.p95_cycles, stat_E4.median_ns, stat_E4.p95_ns);
    printf("    \"E_tbb_contended_6thr\": {\"median_cycles\": %.4f, \"p95_cycles\": %.4f, \"median_ns\": %.4f, \"p95_ns\": %.4f}\n",
           stat_E6.median_cycles, stat_E6.p95_cycles, stat_E6.median_ns, stat_E6.p95_ns);
    printf("  },\n");
    printf("  \"derived\": {\n");
    printf("    \"C_fx_ns\": %.4f,\n", stat_B.median_ns - stat_A.median_ns);
    printf("    \"C_hook_ns\": %.4f,\n", stat_C.median_ns - stat_A.median_ns);
    printf("    \"C_hook_cycles\": %.4f,\n", stat_C.median_cycles - stat_A.median_cycles);
    printf("    \"C_hook_handled_ns\": %.4f,\n", stat_Ch.median_ns - stat_A.median_ns);
    printf("    \"D_vtable_hook_ns\": %.4f,\n", stat_D.median_ns - stat_Dbase.median_ns);
    printf("    \"E4_vs_C_ratio\": %.4f,\n", stat_E4.median_ns / stat_C.median_ns);
    printf("    \"E_vs_C_ratio\": %.4f\n", stat_E6.median_ns / stat_C.median_ns);
    printf("  },\n");
    printf("  \"sink\": %u\n", (unsigned)g_sink);
    printf("}\n");

    VirtualFree(blob_B, 0, MEM_RELEASE);
    VirtualFree(blob_C, 0, MEM_RELEASE);
    VirtualFree(blob_Ch, 0, MEM_RELEASE);
    VirtualFree(blob_D, 0, MEM_RELEASE);
    VirtualFree(blob_E, 0, MEM_RELEASE);
    free(cyc);
    free(ns);
    return 0;
}
