#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "p2_layout.h"
#include "cr_sese_bench_data.h"
#include "cr_sese_nopf_bench_data.h"
#include "cr_sese_varc_bench_data.h"
#include "cr_sese_varc_pf_bench_data.h"

#define NUM_TAGS          220u
#define LIVING_TAGS        40u
#define COUNTRY_STRIDE   8192u
#define RELATION_STRIDE  4096u
#define WARMUP_ITERS       32u
#define MEASURE_ITERS     400u

typedef struct BenchSampleBuf {
    uint64_t *cycles;
    uint32_t  count;
    uint32_t  cap;
} BenchSampleBuf;

static void __cdecl cr_bench_cb(uint32_t cyc_lo, uint32_t cyc_hi, uint32_t variant, void *ctx) {
    (void)variant;
    BenchSampleBuf *buf = (BenchSampleBuf *)ctx;
    if (buf && buf->count < buf->cap) {
        buf->cycles[buf->count++] = ((uint64_t)cyc_hi << 32) | cyc_lo;
    }
}

/* Built dynamically onto a W^X PAGE_EXECUTE_READ page:
 *   movl 0x18(%esp), %eax   ; 8B 44 24 18
 *   movl 0x60(%esp), %ecx   ; 8B 4C 24 60  (out_esp18 ptr)
 *   movl %eax, (%ecx)       ; 89 01
 *   addl $0x64, %esp        ; 83 C4 64
 *   popl %ebp               ; 5D
 *   popl %edi               ; 5F
 *   popl %esi               ; 5E
 *   popl %ebx               ; 5B
 *   ret                     ; C3
 */
static const uint8_t kExitStubCode[] = {
    0x8Bu, 0x44u, 0x24u, 0x18u,
    0x8Bu, 0x4Cu, 0x24u, 0x60u,
    0x89u, 0x01u,
    0x83u, 0xC4u, 0x64u,
    0x5Du, 0x5Fu, 0x5Eu, 0x5Bu,
    0xC3u
};

extern void __cdecl call_cr_sese_region(void *entry_va, void *self, void *country_mgr, int32_t *out_esp18);

static void *alloc_sealed_cr_page(
    const uint8_t *blob, size_t blob_size, size_t cfg_off,
    uint32_t exe_base, uint32_t exit_va, BenchSampleBuf *ctx,
    CRVarCState *varc_state, uint32_t varc_mode
) {
    uint8_t *page = (uint8_t *)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!page) {
        return NULL;
    }
    memcpy(page, blob, blob_size);
    P2CrConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.exe_base = exe_base;
    cfg.exit_va = exit_va;
    cfg.bench_cb = (uint32_t)(uintptr_t)&cr_bench_cb;
    cfg.bench_ctx = (uint32_t)(uintptr_t)ctx;
    cfg.varc_state = (uint32_t)(uintptr_t)varc_state;
    cfg.varc_mode = varc_mode;
    cfg.varc_sync_fn = 0u;
    memcpy(page + cfg_off, &cfg, sizeof(cfg));

    DWORD old_prot = 0;
    if (!VirtualProtect(page, 4096, PAGE_EXECUTE_READ, &old_prot)) {
        VirtualFree(page, 0, MEM_RELEASE);
        return NULL;
    }
    FlushInstructionCache(GetCurrentProcess(), page, blob_size);
    return page;
}

static inline void clflush_line(const void *p) {
    __asm__ volatile ("clflush (%0)" :: "r"(p) : "memory");
}

static void flush_fixture(
    uint8_t * const *entries,
    uint8_t * const *countries,
    uint8_t * const *relations,
    uint8_t *self
) {
    for (uint32_t i = 0; i < NUM_TAGS; ++i) {
        clflush_line(&entries[i]);
        clflush_line(entries[i]);
        clflush_line(countries[i] + 0x9D8u);
        clflush_line(&relations[i]);
        if (relations[i]) {
            clflush_line(relations[i] + 0x70u);
        }
    }
    clflush_line(self + 0x20u);
    clflush_line(self + 0xBE8u);
    __asm__ volatile ("mfence; lfence" ::: "memory");
}

int main(void) {
    /* 1. Mock base spanning RVA 0x00000000 .. 0x00E60000 */
    const size_t mock_size = 0x00E60000u;
    uint8_t *mock_base = (uint8_t *)VirtualAlloc(NULL, mock_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mock_base) {
        fprintf(stderr, "VirtualAlloc(mock_base) failed: %lu\n", (unsigned long)GetLastError());
        return 1;
    }

    /* Stub helpers called inside cr_sese_body.c:
     * 0x000A8300: eax=self -> al=0 (xor eax, eax; ret)
     * 0x00111140: edx=&tag, [esp+4]=other -> al=0 (xor eax, eax; ret 4)
     */
    mock_base[0x000A8300u + 0] = 0x31u;
    mock_base[0x000A8300u + 1] = 0xC0u;
    mock_base[0x000A8300u + 2] = 0xC3u;

    mock_base[0x00111140u + 0] = 0x31u;
    mock_base[0x00111140u + 1] = 0xC0u;
    mock_base[0x00111140u + 2] = 0xC2u;
    mock_base[0x00111140u + 3] = 0x04u;
    mock_base[0x00111140u + 4] = 0x00u;

    uint8_t *exit_stub = (uint8_t *)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!exit_stub) {
        return 2;
    }
    memcpy(exit_stub, kExitStubCode, sizeof(kExitStubCode));
    DWORD old_prot = 0;
    VirtualProtect(exit_stub, 4096, PAGE_EXECUTE_READ, &old_prot);
    FlushInstructionCache(GetCurrentProcess(), exit_stub, sizeof(kExitStubCode));

    /* 2. Scattered country & relation arenas */
    uint8_t *country_arena = (uint8_t *)VirtualAlloc(
        NULL, (size_t)NUM_TAGS * COUNTRY_STRIDE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    uint8_t *rel_arena = (uint8_t *)VirtualAlloc(
        NULL, (size_t)NUM_TAGS * RELATION_STRIDE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    uint8_t **entries = (uint8_t **)VirtualAlloc(
        NULL, (size_t)NUM_TAGS * sizeof(uint8_t *), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    uint8_t **countries = (uint8_t **)VirtualAlloc(
        NULL, (size_t)NUM_TAGS * sizeof(uint8_t *), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    uint8_t **relations = (uint8_t **)VirtualAlloc(
        NULL, (size_t)NUM_TAGS * sizeof(uint8_t *), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!country_arena || !rel_arena || !entries || !countries || !relations) {
        return 3;
    }

    for (uint32_t id = 0; id < NUM_TAGS; ++id) {
        uint32_t slot_c = (id * 131u + 17u) % NUM_TAGS;
        uint32_t slot_r = (id * 173u + 53u) % NUM_TAGS;
        uint8_t *c = country_arena + (size_t)slot_c * COUNTRY_STRIDE;
        uint8_t *r = rel_arena + (size_t)slot_r * RELATION_STRIDE;

        *(uint32_t *)(c + 0x1Cu) = 0x00414141u + id; /* synthetic non-REB tag */
        *(uint32_t *)(c + 0x20u) = id;
        *(uint32_t *)(c + 0x9D8u) = 0x1000u;
        /* ~18.2% living tags (40/220), ~81.8% dead tags (180/220) */
        *(uint32_t *)(c + 0x9DCu) = (id >= 2u && id < 2u + LIVING_TAGS) ? 0x1010u : 0x1000u;

        *(uint32_t *)(r + 0x0Cu) = id;
        countries[id] = c;
        relations[id] = r;
    }
    /* Entry scan order also permuted across scattered arenas */
    for (uint32_t idx = 0; idx < NUM_TAGS; ++idx) {
        uint32_t id = (idx * 79u + 7u) % NUM_TAGS;
        entries[idx] = countries[id];
    }

    uint8_t *self = countries[1];
    *(uint8_t ***)(self + 0xBE8u) = relations;
    *(uint32_t *)(self + 0x142Cu) = 0xFFFFFFFFu;

    uint32_t mgr_tags[2];
    mgr_tags[0] = NUM_TAGS;
    mgr_tags[1] = (uint32_t)(uintptr_t)entries;
    *(uint32_t **)(mock_base + 0x00E587E4u) = mgr_tags;

    uint8_t *world = (uint8_t *)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    *(uint8_t **)(mock_base + 0x00E588E8u) = world;

    uint64_t nopf_buf[WARMUP_ITERS + MEASURE_ITERS];
    uint64_t vara_buf[WARMUP_ITERS + MEASURE_ITERS];
    uint64_t varc_buf[WARMUP_ITERS + MEASURE_ITERS];
    uint64_t varcpf_buf[WARMUP_ITERS + MEASURE_ITERS];
    BenchSampleBuf nopf_samples   = { nopf_buf,   0u, WARMUP_ITERS + MEASURE_ITERS };
    BenchSampleBuf vara_samples   = { vara_buf,   0u, WARMUP_ITERS + MEASURE_ITERS };
    BenchSampleBuf varc_samples   = { varc_buf,   0u, WARMUP_ITERS + MEASURE_ITERS };
    BenchSampleBuf varcpf_samples = { varcpf_buf, 0u, WARMUP_ITERS + MEASURE_ITERS };

    CRVarCState varc_state;
    CRVarCState varcpf_state;
    memset(&varc_state, 0, sizeof(varc_state));
    memset(&varcpf_state, 0, sizeof(varcpf_state));

    uint8_t *page_nopf = (uint8_t *)alloc_sealed_cr_page(
        P2_CR_SESE_NOPF_BENCH_BLOB,
        P2_CR_SESE_NOPF_BENCH_SIZE,
        P2_CR_SESE_NOPF_BENCH_OFF_CR_SESE_CONFIG,
        (uint32_t)(uintptr_t)mock_base,
        (uint32_t)(uintptr_t)exit_stub,
        &nopf_samples,
        NULL, 0u
    );
    uint8_t *page_vara = (uint8_t *)alloc_sealed_cr_page(
        P2_CR_SESE_BENCH_BLOB,
        P2_CR_SESE_BENCH_SIZE,
        P2_CR_SESE_BENCH_OFF_CR_SESE_CONFIG,
        (uint32_t)(uintptr_t)mock_base,
        (uint32_t)(uintptr_t)exit_stub,
        &vara_samples,
        NULL, 0u
    );
    uint8_t *page_varc = (uint8_t *)alloc_sealed_cr_page(
        P2_CR_SESE_VARC_BENCH_BLOB,
        P2_CR_SESE_VARC_BENCH_SIZE,
        P2_CR_SESE_VARC_BENCH_OFF_CR_SESE_CONFIG,
        (uint32_t)(uintptr_t)mock_base,
        (uint32_t)(uintptr_t)exit_stub,
        &varc_samples,
        &varc_state, P2_VARC_PROD
    );
    uint8_t *page_varcpf = (uint8_t *)alloc_sealed_cr_page(
        P2_CR_SESE_VARC_PF_BENCH_BLOB,
        P2_CR_SESE_VARC_PF_BENCH_SIZE,
        P2_CR_SESE_VARC_PF_BENCH_OFF_CR_SESE_CONFIG,
        (uint32_t)(uintptr_t)mock_base,
        (uint32_t)(uintptr_t)exit_stub,
        &varcpf_samples,
        &varcpf_state, P2_VARC_PROD
    );
    if (!page_nopf || !page_vara || !page_varc || !page_varcpf) {
        return 4;
    }
    void *entry_nopf   = page_nopf   + P2_CR_SESE_NOPF_BENCH_OFF_CR_SESE_ENTRY;
    void *entry_vara   = page_vara   + P2_CR_SESE_BENCH_OFF_CR_SESE_ENTRY;
    void *entry_varc   = page_varc   + P2_CR_SESE_VARC_BENCH_OFF_CR_SESE_ENTRY;
    void *entry_varcpf = page_varcpf + P2_CR_SESE_VARC_PF_BENCH_OFF_CR_SESE_ENTRY;

    /* 3. Cold clflush pass (interleaved A/B/C/D) */
    for (uint32_t i = 0; i < WARMUP_ITERS + MEASURE_ITERS; ++i) {
        int32_t e_a = -1, e_b = -1, e_c = -1, e_d = -1;
        flush_fixture(entries, countries, relations, self);
        call_cr_sese_region(entry_nopf, self, mgr_tags, &e_a);
        flush_fixture(entries, countries, relations, self);
        call_cr_sese_region(entry_vara, self, mgr_tags, &e_b);
        flush_fixture(entries, countries, relations, self);
        clflush_line(&varc_state.alive_bits[0]);
        clflush_line(&varc_state.initialized);
        __asm__ volatile ("mfence; lfence" ::: "memory");
        call_cr_sese_region(entry_varc, self, mgr_tags, &e_c);
        flush_fixture(entries, countries, relations, self);
        clflush_line(&varcpf_state.alive_bits[0]);
        clflush_line(&varcpf_state.initialized);
        __asm__ volatile ("mfence; lfence" ::: "memory");
        call_cr_sese_region(entry_varcpf, self, mgr_tags, &e_d);
        if (e_a != (int32_t)NUM_TAGS || e_b != (int32_t)NUM_TAGS ||
            e_c != (int32_t)NUM_TAGS || e_d != (int32_t)NUM_TAGS) {
            fprintf(stderr, "Equivalence mismatch: %d %d %d %d\n", e_a, e_b, e_c, e_d);
            return 5;
        }
    }
    for (uint32_t i = WARMUP_ITERS; i < WARMUP_ITERS + MEASURE_ITERS; ++i) {
        printf("SAMPLE cold_clflush nopf %llu\n", (unsigned long long)nopf_buf[i]);
        printf("SAMPLE cold_clflush var_a %llu\n", (unsigned long long)vara_buf[i]);
        printf("SAMPLE cold_clflush var_c %llu\n", (unsigned long long)varc_buf[i]);
        printf("SAMPLE cold_clflush var_c_pf %llu\n", (unsigned long long)varcpf_buf[i]);
    }

    /* 4. Warm cached pass (no clflush, interleaved A/B/C/D) */
    nopf_samples.count = 0u;
    vara_samples.count = 0u;
    varc_samples.count = 0u;
    varcpf_samples.count = 0u;
    for (uint32_t i = 0; i < WARMUP_ITERS + MEASURE_ITERS; ++i) {
        int32_t e_a = -1, e_b = -1, e_c = -1, e_d = -1;
        call_cr_sese_region(entry_nopf, self, mgr_tags, &e_a);
        call_cr_sese_region(entry_vara, self, mgr_tags, &e_b);
        call_cr_sese_region(entry_varc, self, mgr_tags, &e_c);
        call_cr_sese_region(entry_varcpf, self, mgr_tags, &e_d);
        if (e_a != (int32_t)NUM_TAGS || e_b != (int32_t)NUM_TAGS ||
            e_c != (int32_t)NUM_TAGS || e_d != (int32_t)NUM_TAGS) {
            return 6;
        }
    }
    for (uint32_t i = WARMUP_ITERS; i < WARMUP_ITERS + MEASURE_ITERS; ++i) {
        printf("SAMPLE warm_cached nopf %llu\n", (unsigned long long)nopf_buf[i]);
        printf("SAMPLE warm_cached var_a %llu\n", (unsigned long long)vara_buf[i]);
        printf("SAMPLE warm_cached var_c %llu\n", (unsigned long long)varc_buf[i]);
        printf("SAMPLE warm_cached var_c_pf %llu\n", (unsigned long long)varcpf_buf[i]);
    }

    VirtualFree(page_nopf, 0, MEM_RELEASE);
    VirtualFree(page_vara, 0, MEM_RELEASE);
    VirtualFree(page_varc, 0, MEM_RELEASE);
    VirtualFree(page_varcpf, 0, MEM_RELEASE);
    VirtualFree(exit_stub, 0, MEM_RELEASE);
    VirtualFree(world, 0, MEM_RELEASE);
    VirtualFree(relations, 0, MEM_RELEASE);
    VirtualFree(countries, 0, MEM_RELEASE);
    VirtualFree(entries, 0, MEM_RELEASE);
    VirtualFree(rel_arena, 0, MEM_RELEASE);
    VirtualFree(country_arena, 0, MEM_RELEASE);
    VirtualFree(mock_base, 0, MEM_RELEASE);
    return 0;
}
