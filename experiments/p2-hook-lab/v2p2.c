#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "p2_layout.h"
#include "build/hook_blob_data.h"
#ifdef P2_CR_BENCH_DLL
#include "build/cr_sese_bench_data.h"
#include "build/cr_sese_varc_bench_data.h"
#define P2_CR_ACTIVE_BLOB          P2_CR_SESE_BENCH_BLOB
#define P2_CR_ACTIVE_SIZE          P2_CR_SESE_BENCH_SIZE
#define P2_CR_ACTIVE_ENTRY         P2_CR_SESE_BENCH_OFF_CR_SESE_ENTRY
#define P2_CR_ACTIVE_CONFIG        P2_CR_SESE_BENCH_OFF_CR_SESE_CONFIG
#define P2_CR_VARC_ACTIVE_BLOB     P2_CR_SESE_VARC_BENCH_BLOB
#define P2_CR_VARC_ACTIVE_SIZE     P2_CR_SESE_VARC_BENCH_SIZE
#define P2_CR_VARC_ACTIVE_ENTRY    P2_CR_SESE_VARC_BENCH_OFF_CR_SESE_ENTRY
#define P2_CR_VARC_ACTIVE_CONFIG   P2_CR_SESE_VARC_BENCH_OFF_CR_SESE_CONFIG
#else
#include "build/cr_sese_data.h"
#include "build/cr_sese_varc_data.h"
#define P2_CR_ACTIVE_BLOB          P2_CR_SESE_BLOB
#define P2_CR_ACTIVE_SIZE          P2_CR_SESE_SIZE
#define P2_CR_ACTIVE_ENTRY         P2_CR_SESE_OFF_CR_SESE_ENTRY
#define P2_CR_ACTIVE_CONFIG        P2_CR_SESE_OFF_CR_SESE_CONFIG
#define P2_CR_VARC_ACTIVE_BLOB     P2_CR_SESE_VARC_BLOB
#define P2_CR_VARC_ACTIVE_SIZE     P2_CR_SESE_VARC_SIZE
#define P2_CR_VARC_ACTIVE_ENTRY    P2_CR_SESE_VARC_OFF_CR_SESE_ENTRY
#define P2_CR_VARC_ACTIVE_CONFIG   P2_CR_SESE_VARC_OFF_CR_SESE_CONFIG
#endif

/* Target PE fingerprint for base-game/v2game.exe (SHA-256 62d48c20...) */
#define V2_SIZE_OF_IMAGE     0x01092000u
#define V2_ENTRY_POINT_RVA   0x006B0F91u
#define V2_PE_CHECKSUM       0x00BC1E13u

typedef struct P2HookSpec {
    const wchar_t *ini_key;
    uint32_t site_rva;
    uint32_t expected_target_rva;
    uint32_t arg_bytes;
    uint32_t handler_fn;
    uint32_t flags;
    int      is_vtable_slot;
} P2HookSpec;

static void log_msg(const TGLHost *h, const char *msg) {
    if (h && h->log && msg) {
        h->log(h, msg);
    }
}

static int verify_target_pe(const TGLHost *h) {
    if (!h || !h->exe_base) {
        return 0;
    }
    const uint8_t *base = (const uint8_t *)h->exe_base;
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }
    const IMAGE_NT_HEADERS32 *nt = (const IMAGE_NT_HEADERS32 *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
        return 0;
    }
    if (nt->OptionalHeader.SizeOfImage != V2_SIZE_OF_IMAGE) {
        return 0;
    }
    if (nt->OptionalHeader.AddressOfEntryPoint != V2_ENTRY_POINT_RVA) {
        return 0;
    }
    if (nt->OptionalHeader.CheckSum != V2_PE_CHECKSUM) {
        return 0;
    }
    return 1;
}

static uint32_t parse_mode_ini(const wchar_t *ini_path, const wchar_t *key) {
    wchar_t buf[32];
    if (!ini_path || !key) {
        return P2_MODE_OFF;
    }
    DWORD n = GetPrivateProfileStringW(L"hooks", key, L"off", buf, 32, ini_path);
    if (n == 0) {
        return P2_MODE_OFF;
    }
    if (_wcsicmp(buf, L"1") == 0 || _wcsicmp(buf, L"prod") == 0) {
        return P2_MODE_PROD;
    }
    if (_wcsicmp(buf, L"2") == 0 || _wcsicmp(buf, L"shadow") == 0 || _wcsicmp(buf, L"shadow-compare") == 0) {
        return P2_MODE_SHADOW;
    }
    return P2_MODE_OFF;
}

static uint32_t parse_varc_mode_ini(const wchar_t *ini_path, const wchar_t *key) {
    wchar_t buf[32];
    if (!ini_path || !key) {
        return P2_VARC_OFF;
    }
    DWORD n = GetPrivateProfileStringW(L"hooks", key, L"off", buf, 32, ini_path);
    if (n == 0) {
        return P2_VARC_OFF;
    }
    if (_wcsicmp(buf, L"validate") == 0 || _wcsicmp(buf, L"1") == 0) {
        return P2_VARC_VALIDATE;
    }
    if (_wcsicmp(buf, L"prod") == 0 || _wcsicmp(buf, L"2") == 0) {
        return P2_VARC_PROD;
    }
    return P2_VARC_OFF;
}

static int valid_arg_bytes(uint32_t arg_bytes) {
    return arg_bytes == 0u || arg_bytes == 4u || arg_bytes == 8u || arg_bytes == 12u;
}

/* Allocate, configure, and seal a reloc-free PIC hook blob as PAGE_EXECUTE_READ (W^X). */
static void *alloc_sealed_pic_blob(
    uint32_t original_target,
    uint32_t handler_fn,
    uint32_t mode,
    uint32_t arg_bytes,
    uint32_t flags,
    uint32_t user_data
) {
    if (!valid_arg_bytes(arg_bytes)) {
        return NULL;
    }
    uint8_t *page = (uint8_t *)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!page) {
        return NULL;
    }
    memcpy(page, P2_HOOK_BLOB, P2_BLOB_SIZE);

    P2HookConfig cfg;
    cfg.original_target = original_target;
    cfg.handler_fn = handler_fn;
    cfg.mode = mode;
    cfg.arg_bytes = arg_bytes;
    cfg.flags = flags;
    cfg.tls_slot = 0xFFFFFFFFu;
    cfg.user_data = user_data;
    cfg.reserved = 0u;
    memcpy(page + P2_OFF_HOOK_CONFIG, &cfg, sizeof(cfg));

    DWORD old_prot = 0;
    if (!VirtualProtect(page, 4096, PAGE_EXECUTE_READ, &old_prot)) {
        VirtualFree(page, 0, MEM_RELEASE);
        return NULL;
    }
    FlushInstructionCache(GetCurrentProcess(), page, P2_BLOB_SIZE);
    return page;
}

static int patch_call_site_rel32(uint8_t *call_site, uint32_t expected_target, void *hook_entry) {
    if (call_site[0] != 0xE8) {
        return 0;
    }
    int32_t orig_rel = 0;
    memcpy(&orig_rel, call_site + 1, sizeof(orig_rel));
    uint32_t actual_target = (uint32_t)(uintptr_t)(call_site + 5) + (uint32_t)orig_rel;
    if (actual_target != expected_target) {
        return 0;
    }

    DWORD old_prot = 0;
    if (!VirtualProtect(call_site, 5, PAGE_EXECUTE_READWRITE, &old_prot)) {
        return 0;
    }
    int32_t new_rel = (int32_t)((uintptr_t)hook_entry - (uintptr_t)(call_site + 5));
    memcpy(call_site + 1, &new_rel, sizeof(new_rel));
    DWORD dummy = 0;
    VirtualProtect(call_site, 5, old_prot, &dummy);
    FlushInstructionCache(GetCurrentProcess(), call_site, 5);
    return 1;
}

static int patch_vtable_slot(uint32_t *slot_addr, uint32_t expected_target, void *hook_entry) {
    if (*slot_addr != expected_target) {
        return 0;
    }
    DWORD old_prot = 0;
    if (!VirtualProtect(slot_addr, 4, PAGE_READWRITE, &old_prot)) {
        return 0;
    }
    *slot_addr = (uint32_t)(uintptr_t)hook_entry;
    DWORD dummy = 0;
    VirtualProtect(slot_addr, 4, old_prot, &dummy);
    return 1;
}

/* HighPerfWinClock pilot constants (RVAs relative to v2game.exe ImageBase 0x00400000) */
#define RVA_HPWC_CTOR_SKIP     0x0067B433u  /* VA 0x00A7B433: mov edi, [0x013F075C] (6 B) */
#define RVA_HPWC_TAIL_GLOBAL   0x00FF075Cu  /* VA 0x013F075C: global tail ptr */
#define RVA_HPWC_DTOR_ENTRY    0x0067B490u  /* VA 0x00A7B490: ~HighPerfWinClock */
#define RVA_HPWC_DTOR_VTABLE   0x00A43A88u  /* VA 0x00E43A88: vtable[0] slot */
#define RVA_HPWC_BASE_VTABLE   0x00A388A8u  /* VA 0x00E388A8: base vtable restored at dtor end */
#define RVA_OP_DELETE          0x006AE91Bu  /* VA 0x00AAE91B: __cdecl operator delete(void*) */

static int patch_bytes(uint8_t *dst, const uint8_t *new_bytes, size_t len, uint8_t *saved_out) {
    DWORD old_prot = 0;
    if (!VirtualProtect(dst, len, PAGE_EXECUTE_READWRITE, &old_prot)) {
        return 0;
    }
    if (saved_out) {
        memcpy(saved_out, dst, len);
    }
    memcpy(dst, new_bytes, len);
    DWORD dummy = 0;
    VirtualProtect(dst, len, old_prot, &dummy);
    FlushInstructionCache(GetCurrentProcess(), dst, len);
    return 1;
}

/*
 * P2 C handler for HighPerfWinClock::~HighPerfWinClock (0x00A7B490, __thiscall, arg_bytes=4).
 * Zero shared mutable globals: exe_base is passed via immutable cfg->user_data.
 * Restores base vtable 0x00E388A8, optionally calls operator delete(this), sets EAX = this.
 */
static int __cdecl p2_dtor_a7b490_handler(P2SavedState *regs, P2FxSave *fx, const P2HookConfig *cfg) {
    (void)fx;
    uint32_t this_ptr = regs->ecx;
    if (!this_ptr) {
        return P2_ACT_FALLBACK;
    }
    uintptr_t base = (uintptr_t)cfg->user_data;
    uint32_t flags = regs->args[0];

    *(volatile uint32_t *)(uintptr_t)this_ptr = (uint32_t)(base + RVA_HPWC_BASE_VTABLE);
    if ((flags & 1u) != 0u) {
        typedef void (__cdecl *op_delete_fn)(void *);
        op_delete_fn fn_del = (op_delete_fn)(uintptr_t)(base + RVA_OP_DELETE);
        fn_del((void *)(uintptr_t)this_ptr);
    }
    regs->eax = this_ptr;
    return P2_ACT_HANDLED;
}

static int install_highperfwinclock_pilot(const TGLHost *h, const uint8_t *base) {
    uint32_t mode = parse_mode_ini(h->config_file, L"fn_00a7b490");
    if (mode == P2_MODE_OFF) {
        return 0;
    }
    if (mode == P2_MODE_SHADOW) {
        log_msg(h, "v2p2: fn_00a7b490 mode=shadow rejected (no shadow comparator registered); leaving unpatched.");
        return 0;
    }
    if (h->exe_size != 0u && h->exe_size < (RVA_HPWC_DTOR_VTABLE + 4u)) {
        log_msg(h, "v2p2: fn_00a7b490 exe_size too small; leaving unpatched.");
        return 0;
    }

    uint8_t *ctor_site = (uint8_t *)(uintptr_t)(base + RVA_HPWC_CTOR_SKIP);
    uint32_t *dtor_slot = (uint32_t *)(uintptr_t)(base + RVA_HPWC_DTOR_VTABLE);
    uint32_t orig_dtor_va = (uint32_t)(uintptr_t)(base + RVA_HPWC_DTOR_ENTRY);
    const uint8_t *dtor_entry = (const uint8_t *)(uintptr_t)orig_dtor_va;

    /* 1. Verify ctor skip site: 8b 3d <base + RVA_HPWC_TAIL_GLOBAL> */
    uint32_t disp_va = 0;
    memcpy(&disp_va, ctor_site + 2, sizeof(disp_va));
    if (ctor_site[0] != 0x8Bu || ctor_site[1] != 0x3Du ||
        disp_va != (uint32_t)(uintptr_t)(base + RVA_HPWC_TAIL_GLOBAL)) {
        log_msg(h, "v2p2: fn_00a7b490 ctor site signature mismatch; leaving unpatched.");
        return 0;
    }

    /* 2. Verify dtor vtable slot & prologue signature */
    static const uint8_t kDtorPrologue[6] = { 0x55u, 0x8Bu, 0xECu, 0x56u, 0x8Bu, 0xF1u };
    if (*dtor_slot != orig_dtor_va || memcmp(dtor_entry, kDtorPrologue, sizeof(kDtorPrologue)) != 0) {
        log_msg(h, "v2p2: fn_00a7b490 dtor signature mismatch; leaving unpatched.");
        return 0;
    }

    /* 3. Allocate & seal W^X PIC blob before modifying target image */
    void *blob = alloc_sealed_pic_blob(
        orig_dtor_va,
        (uint32_t)(uintptr_t)&p2_dtor_a7b490_handler,
        P2_MODE_PROD,
        4u,
        0u,
        (uint32_t)(uintptr_t)base
    );
    if (!blob) {
        log_msg(h, "v2p2: fn_00a7b490 failed to allocate/seal PIC blob.");
        return 0;
    }

    /* 4. Atomic paired patch: ctor inline skip (add esp, 4; jmp short 0x00A7B476; nop) + vtable[0] */
    static const uint8_t kCtorSkipPatch[6] = { 0x83u, 0xC4u, 0x04u, 0xEBu, 0x3Eu, 0x90u };
    uint8_t saved_ctor[6];
    if (!patch_bytes(ctor_site, kCtorSkipPatch, sizeof(kCtorSkipPatch), saved_ctor)) {
        VirtualFree(blob, 0, MEM_RELEASE);
        log_msg(h, "v2p2: fn_00a7b490 ctor VirtualProtect failed.");
        return 0;
    }
    if (!patch_vtable_slot(dtor_slot, orig_dtor_va, (uint8_t *)blob + P2_OFF_HOOK_ENTRY)) {
        patch_bytes(ctor_site, saved_ctor, sizeof(saved_ctor), NULL);
        VirtualFree(blob, 0, MEM_RELEASE);
        log_msg(h, "v2p2: fn_00a7b490 dtor vtable patch failed; ctor rolled back.");
        return 0;
    }

    log_msg(h, "v2p2: fn_00a7b490 paired HighPerfWinClock pilot installed (ctor skip + P2 PIC dtor).");
    return 1;
}

/* Country_Recalculate SESE [0x00515EA6, 0x00516286) RVAs (ImageBase 0x00400000) */
#define RVA_CR_SESE_ENTRY      0x00115EA6u  /* VA 0x00515EA6: 8b 54 24 28 8b 02 (6 B) */
#define RVA_CR_SESE_EXIT       0x00116286u  /* VA 0x00516286: 8b 83 00 0a 00 00 (6 B) */

#ifdef P2_CR_BENCH_DLL
typedef struct CrBenchTlsStats {
    uint64_t t0;
    uint64_t total_cycles;
    uint64_t calls;
    uint32_t variant;
} CrBenchTlsStats;

static DWORD g_cr_bench_tls = TLS_OUT_OF_INDEXES;

static CrBenchTlsStats *cr_bench_tls_get(void) {
    if (g_cr_bench_tls == TLS_OUT_OF_INDEXES) {
        return NULL;
    }
    CrBenchTlsStats *st = (CrBenchTlsStats *)TlsGetValue(g_cr_bench_tls);
    if (!st) {
        st = (CrBenchTlsStats *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CrBenchTlsStats));
        if (st) {
            TlsSetValue(g_cr_bench_tls, st);
        }
    }
    return st;
}

static void __cdecl cr_bench_record_cb(uint32_t cyc_lo, uint32_t cyc_hi, uint32_t variant, void *ctx) {
    (void)ctx;
    CrBenchTlsStats *st = cr_bench_tls_get();
    if (st) {
        st->total_cycles += ((uint64_t)cyc_hi << 32) | cyc_lo;
        st->calls += 1u;
        st->variant = variant;
    }
}

__declspec(dllexport) int __cdecl v2p2_cr_bench_snapshot(uint64_t *total_cycles, uint64_t *calls, uint32_t *variant) {
    CrBenchTlsStats *st = (g_cr_bench_tls != TLS_OUT_OF_INDEXES) ? (CrBenchTlsStats *)TlsGetValue(g_cr_bench_tls) : NULL;
    if (!st) {
        return 0;
    }
    if (total_cycles) *total_cycles = st->total_cycles;
    if (calls) *calls = st->calls;
    if (variant) *variant = st->variant;
    return 1;
}
#endif

static int install_country_recalculate_sese(const TGLHost *h, const uint8_t *base) {
    uint32_t mode = parse_mode_ini(h->config_file, L"fn_00515ea6");
    if (mode == P2_MODE_OFF) {
        return 0;
    }
    if (mode == P2_MODE_SHADOW) {
        log_msg(h, "v2p2: fn_00515ea6 mode=shadow rejected (no shadow comparator registered); leaving unpatched.");
        return 0;
    }
    if (h->exe_size != 0u && h->exe_size < (RVA_CR_SESE_EXIT + 6u)) {
        log_msg(h, "v2p2: fn_00515ea6 exe_size too small; leaving unpatched.");
        return 0;
    }

    uint8_t *entry_site = (uint8_t *)(uintptr_t)(base + RVA_CR_SESE_ENTRY);
    const uint8_t *exit_site = (const uint8_t *)(uintptr_t)(base + RVA_CR_SESE_EXIT);
    static const uint8_t kExpectedEntry[6] = { 0x8Bu, 0x54u, 0x24u, 0x28u, 0x8Bu, 0x02u };
    static const uint8_t kExpectedExit[6]  = { 0x8Bu, 0x83u, 0x00u, 0x0Au, 0x00u, 0x00u };
    if (memcmp(entry_site, kExpectedEntry, sizeof(kExpectedEntry)) != 0 ||
        memcmp(exit_site, kExpectedExit, sizeof(kExpectedExit)) != 0) {
        log_msg(h, "v2p2: fn_00515ea6 signature mismatch; leaving unpatched.");
        return 0;
    }

    uint8_t *page = (uint8_t *)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!page) {
        log_msg(h, "v2p2: fn_00515ea6 VirtualAlloc failed.");
        return 0;
    }
    memcpy(page, P2_CR_ACTIVE_BLOB, P2_CR_ACTIVE_SIZE);

    P2CrConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.exe_base = (uint32_t)(uintptr_t)base;
    cfg.exit_va = (uint32_t)(uintptr_t)(base + RVA_CR_SESE_EXIT);
#ifdef P2_CR_BENCH_DLL
    if (g_cr_bench_tls == TLS_OUT_OF_INDEXES) {
        g_cr_bench_tls = TlsAlloc();
    }
    cfg.bench_cb = (uint32_t)(uintptr_t)&cr_bench_record_cb;
    cfg.bench_ctx = 0u;
#else
    cfg.bench_cb = 0u;
    cfg.bench_ctx = 0u;
#endif
    memcpy(page + P2_CR_ACTIVE_CONFIG, &cfg, sizeof(cfg));

    DWORD old_prot = 0;
    if (!VirtualProtect(page, 4096, PAGE_EXECUTE_READ, &old_prot)) {
        VirtualFree(page, 0, MEM_RELEASE);
        log_msg(h, "v2p2: fn_00515ea6 VirtualProtect(PAGE_EXECUTE_READ) failed.");
        return 0;
    }
    FlushInstructionCache(GetCurrentProcess(), page, P2_CR_ACTIVE_SIZE);

    uint8_t detour[6];
    detour[0] = 0xE9u;
    int32_t rel = (int32_t)((uintptr_t)(page + P2_CR_ACTIVE_ENTRY) - (uintptr_t)(entry_site + 5));
    memcpy(detour + 1, &rel, sizeof(rel));
    detour[5] = 0x90u;  /* nop */

    if (!patch_bytes(entry_site, detour, sizeof(detour), NULL)) {
        VirtualFree(page, 0, MEM_RELEASE);
        log_msg(h, "v2p2: fn_00515ea6 detour patch failed.");
        return 0;
    }

    log_msg(h, "v2p2: fn_00515ea6 Country_Recalculate SESE variant(a) installed (W^X sealed).");
    return 1;
}

/* Variant (c) compact living-tag bitmask state & 3-writer hooks */
#define RVA_GLOBAL_COUNTRY_MGR   0x00E587E4u  /* VA 0x012587E4 */
#define RVA_FN_SET_OWNER         0x000B52E0u  /* VA 0x004B52E0 __thiscall, ret 0x10 */
#define RVA_FN_COUNTRY_RESET     0x00103020u  /* VA 0x00503020 __stdcall, ret 4 */
#define RVA_FN_WORLD_CHANGE_TAG  0x002881D0u  /* VA 0x006881D0 __stdcall, ret 0xC */

extern void v2p2_wrap_set_owner(void);
extern void v2p2_wrap_country_reset(void);
extern void v2p2_wrap_world_change_tag(void);

uint32_t v2p2_orig_set_owner = 0u;
uint32_t v2p2_orig_country_reset = 0u;
uint32_t v2p2_orig_world_change_tag = 0u;

static CRVarCState g_cr_varc;
static wchar_t g_cr_varc_log_path[MAX_PATH];

static void v2p2_varc_init_log_path(const wchar_t *ini_path) {
    g_cr_varc_log_path[0] = L'\0';
    if (!ini_path || !ini_path[0]) {
        return;
    }
    wcsncpy(g_cr_varc_log_path, ini_path, MAX_PATH - 1u);
    g_cr_varc_log_path[MAX_PATH - 1u] = L'\0';
    wchar_t *slash = wcsrchr(g_cr_varc_log_path, L'\\');
    wchar_t *fslash = wcsrchr(g_cr_varc_log_path, L'/');
    wchar_t *sep = (slash && fslash) ? ((slash > fslash) ? slash : fslash) : (slash ? slash : fslash);
    if (sep) {
        size_t dir_len = (size_t)(sep - g_cr_varc_log_path + 1);
        if (dir_len + 26u < MAX_PATH) {
            wcscpy(sep + 1, L"v2p2_varc_validate.log");
            return;
        }
    }
    wcscpy(g_cr_varc_log_path, L"v2p2_varc_validate.log");
}

static void __cdecl v2p2_varc_mismatch_cb(uint32_t idx, uint32_t expected, uint32_t actual, uint32_t count) {
    LARGE_INTEGER qpc;
    qpc.QuadPart = 0;
    QueryPerformanceCounter(&qpc);
    char msg[160];
    snprintf(
        msg, sizeof(msg),
        "v2p2_varc_validate: mismatch #%u idx=%u expected=%u actual=%u clock=%llu\r\n",
        (unsigned)count, (unsigned)idx, (unsigned)expected, (unsigned)actual,
        (unsigned long long)qpc.QuadPart
    );
    OutputDebugStringA(msg);
    if (g_cr_varc_log_path[0] != L'\0') {
        FILE *f = _wfopen(g_cr_varc_log_path, L"ab");
        if (f) {
            fputs(msg, f);
            fclose(f);
        }
    }
}

static void v2p2_refresh_tag_bit(CRVarCState *st, uint32_t id) {
    if (!st->initialized || id == 0u || id >= st->total_tags || id >= P2_VARC_MAX_TAGS) {
        return;
    }
    uint32_t *country_mgr = *(uint32_t * const *)(uintptr_t)(st->exe_base + RVA_GLOBAL_COUNTRY_MGR);
    if (!country_mgr) {
        return;
    }
    uint32_t cur_total = *country_mgr;
    uint8_t * const *entries = *(uint8_t * const **)(country_mgr + 1);
    if (!entries || cur_total != st->total_tags || (uint32_t)(uintptr_t)entries != st->entries_ptr) {
        st->dirty = 1u;
        return;
    }
    uint8_t *entry = entries[id];
    if (!entry) {
        return;
    }
    uint32_t other_id = *(const uint32_t *)(entry + 0x20u);
    uint32_t other_tag = *(const uint32_t *)(entry + 0x1Cu);
    uint32_t alive = 0u;
    if (other_id != 0u && (other_tag & 0x00FFFFFFu) != 0x00424552u && other_id < cur_total) {
        uint8_t *other = entries[other_id];
        if (other) {
            int32_t prov_diff = *(const int32_t *)(other + 0x9DCu) - *(const int32_t *)(other + 0x9D8u);
            if ((prov_diff & ~3) > 0) {
                alive = 1u;
            }
        }
    }
    uint32_t word = id >> 5;
    uint32_t bit = 1u << (id & 31u);
    if (alive) {
        st->alive_bits[word] |= bit;
    } else {
        st->alive_bits[word] &= ~bit;
    }
}

void __cdecl v2p2_on_post_set_owner(void *prov, uint32_t old_id) {
    if (!g_cr_varc.initialized || !prov) {
        return;
    }
    uint32_t new_id = *(const uint32_t *)((const uint8_t *)prov + 0x12Cu);
    if (old_id != 0u) {
        v2p2_refresh_tag_bit(&g_cr_varc, old_id);
    }
    if (new_id != 0u && new_id != old_id) {
        v2p2_refresh_tag_bit(&g_cr_varc, new_id);
    }
}

void __cdecl v2p2_on_post_country_reset(void *country) {
    if (!g_cr_varc.initialized || !country) {
        return;
    }
    uint32_t id = *(const uint32_t *)((const uint8_t *)country + 0x20u);
    if (id != 0u) {
        v2p2_refresh_tag_bit(&g_cr_varc, id);
    }
}

void __cdecl v2p2_on_pre_world_change_tag(void) {
    if (g_cr_varc.initialized) {
        g_cr_varc.dirty = 1u;
    }
}

void __cdecl v2p2_on_post_world_change_tag(uint32_t id1, uint32_t id2) {
    if (!g_cr_varc.initialized) {
        return;
    }
    if (g_cr_varc.dirty != 0u) {
        v2p2_refresh_tag_bit(&g_cr_varc, id1);
        v2p2_refresh_tag_bit(&g_cr_varc, id2);
        if (g_cr_varc.dirty != 0u) {
            /* If total_tags/entries_ptr changed, keep dirty=1 so next SESE rebuilds;
             * otherwise the swap is now reflected in alive_bits for id1 and id2. */
            uint32_t *country_mgr = *(uint32_t * const *)(uintptr_t)(g_cr_varc.exe_base + RVA_GLOBAL_COUNTRY_MGR);
            if (country_mgr && *country_mgr == g_cr_varc.total_tags &&
                (uint32_t)(uintptr_t)*(uint8_t * const **)(country_mgr + 1) == g_cr_varc.entries_ptr) {
                g_cr_varc.dirty = 0u;
            }
        }
    }
}

typedef struct VarcCallSite {
    uint32_t call_rva;
    uint32_t target_rva;
    void    *wrapper_fn;
} VarcCallSite;

static int restore_call_site_rel32(uint8_t *call_site, uint32_t orig_target) {
    uint8_t patch[5];
    patch[0] = 0xE8u;
    int32_t rel = (int32_t)(orig_target - (uint32_t)(uintptr_t)(call_site + 5));
    memcpy(patch + 1, &rel, sizeof(rel));
    return patch_bytes(call_site, patch, sizeof(patch), NULL);
}

static int install_country_recalculate_varc(const TGLHost *h, const uint8_t *base, int sese_already_patched) {
    uint32_t mode = parse_varc_mode_ini(h->config_file, L"fn_00515ea6_varc");
    if (mode == P2_VARC_OFF) {
        return 0;
    }
    if (sese_already_patched) {
        log_msg(h, "v2p2: fn_00515ea6_varc skipped (conflict: fn_00515ea6 already patched).");
        return 0;
    }
    if (h->exe_size != 0u && h->exe_size < 0x00480F88u) {
        log_msg(h, "v2p2: fn_00515ea6_varc exe_size too small; leaving unpatched.");
        return 0;
    }

    uint8_t *entry_site = (uint8_t *)(uintptr_t)(base + RVA_CR_SESE_ENTRY);
    const uint8_t *exit_site = (const uint8_t *)(uintptr_t)(base + RVA_CR_SESE_EXIT);
    static const uint8_t kExpectedEntry[6] = { 0x8Bu, 0x54u, 0x24u, 0x28u, 0x8Bu, 0x02u };
    static const uint8_t kExpectedExit[6]  = { 0x8Bu, 0x83u, 0x00u, 0x0Au, 0x00u, 0x00u };
    if (memcmp(entry_site, kExpectedEntry, sizeof(kExpectedEntry)) != 0 ||
        memcmp(exit_site, kExpectedExit, sizeof(kExpectedExit)) != 0) {
        log_msg(h, "v2p2: fn_00515ea6_varc SESE signature mismatch; leaving unpatched.");
        return 0;
    }

    static const VarcCallSite kVarcWriterSites[] = {
        /* All 7 callers of CProvince::SetOwner (0x004B52E0) */
        { 0x000A9B5Bu, RVA_FN_SET_OWNER,        (void *)&v2p2_wrap_set_owner },
        { 0x000B5965u, RVA_FN_SET_OWNER,        (void *)&v2p2_wrap_set_owner },
        { 0x000B5CC5u, RVA_FN_SET_OWNER,        (void *)&v2p2_wrap_set_owner },
        { 0x000EC6F4u, RVA_FN_SET_OWNER,        (void *)&v2p2_wrap_set_owner },
        { 0x000F9900u, RVA_FN_SET_OWNER,        (void *)&v2p2_wrap_set_owner },
        { 0x00137170u, RVA_FN_SET_OWNER,        (void *)&v2p2_wrap_set_owner },
        { 0x001F4020u, RVA_FN_SET_OWNER,        (void *)&v2p2_wrap_set_owner },
        /* Both callers of CCountry::Reset (0x00503020) */
        { 0x000F8284u, RVA_FN_COUNTRY_RESET,    (void *)&v2p2_wrap_country_reset },
        { 0x0027E78Au, RVA_FN_COUNTRY_RESET,    (void *)&v2p2_wrap_country_reset },
        /* Caller of CWorld::ChangeTag (0x006881D0) */
        { 0x00480F83u, RVA_FN_WORLD_CHANGE_TAG, (void *)&v2p2_wrap_world_change_tag },
    };
    const size_t n_sites = sizeof(kVarcWriterSites) / sizeof(kVarcWriterSites[0]);

    /* Initialize bitmask state cleanly before patching any call sites */
    memset(&g_cr_varc, 0, sizeof(g_cr_varc));
    g_cr_varc.exe_base = (uint32_t)(uintptr_t)base;
    g_cr_varc.validate_mode = (mode == P2_VARC_VALIDATE) ? 1u : 0u;
    v2p2_varc_init_log_path(h->config_file);
    g_cr_varc.mismatch_cb = (uint32_t)(uintptr_t)&v2p2_varc_mismatch_cb;

    v2p2_orig_set_owner = (uint32_t)(uintptr_t)(base + RVA_FN_SET_OWNER);
    v2p2_orig_country_reset = (uint32_t)(uintptr_t)(base + RVA_FN_COUNTRY_RESET);
    v2p2_orig_world_change_tag = (uint32_t)(uintptr_t)(base + RVA_FN_WORLD_CHANGE_TAG);

    /* Seal SESE PIC blob BEFORE patching target code */
    uint8_t *page = (uint8_t *)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!page) {
        log_msg(h, "v2p2: fn_00515ea6_varc VirtualAlloc failed.");
        return 0;
    }
    memcpy(page, P2_CR_VARC_ACTIVE_BLOB, P2_CR_VARC_ACTIVE_SIZE);

    P2CrConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.exe_base = (uint32_t)(uintptr_t)base;
    cfg.exit_va = (uint32_t)(uintptr_t)(base + RVA_CR_SESE_EXIT);
#ifdef P2_CR_BENCH_DLL
    if (g_cr_bench_tls == TLS_OUT_OF_INDEXES) {
        g_cr_bench_tls = TlsAlloc();
    }
    cfg.bench_cb = (uint32_t)(uintptr_t)&cr_bench_record_cb;
    cfg.bench_ctx = 0u;
#else
    cfg.bench_cb = 0u;
    cfg.bench_ctx = 0u;
#endif
    cfg.varc_state = (uint32_t)(uintptr_t)&g_cr_varc;
    cfg.varc_mode = mode;
    cfg.varc_sync_fn = 0u;
    memcpy(page + P2_CR_VARC_ACTIVE_CONFIG, &cfg, sizeof(cfg));

    DWORD old_prot = 0;
    if (!VirtualProtect(page, 4096, PAGE_EXECUTE_READ, &old_prot)) {
        VirtualFree(page, 0, MEM_RELEASE);
        log_msg(h, "v2p2: fn_00515ea6_varc VirtualProtect(PAGE_EXECUTE_READ) failed.");
        return 0;
    }
    FlushInstructionCache(GetCurrentProcess(), page, P2_CR_VARC_ACTIVE_SIZE);

    /* Atomically patch all 10 writer call sites; roll back cleanly on any mismatch */
    size_t patched = 0;
    for (; patched < n_sites; ++patched) {
        uint8_t *csite = (uint8_t *)(uintptr_t)(base + kVarcWriterSites[patched].call_rva);
        uint32_t expect = (uint32_t)(uintptr_t)(base + kVarcWriterSites[patched].target_rva);
        if (!patch_call_site_rel32(csite, expect, kVarcWriterSites[patched].wrapper_fn)) {
            break;
        }
    }
    if (patched < n_sites) {
        for (size_t j = 0; j < patched; ++j) {
            uint8_t *csite = (uint8_t *)(uintptr_t)(base + kVarcWriterSites[j].call_rva);
            uint32_t expect = (uint32_t)(uintptr_t)(base + kVarcWriterSites[j].target_rva);
            restore_call_site_rel32(csite, expect);
        }
        VirtualFree(page, 0, MEM_RELEASE);
        log_msg(h, "v2p2: fn_00515ea6_varc writer call-site signature mismatch; rolled back.");
        return 0;
    }

    uint8_t detour[6];
    detour[0] = 0xE9u;
    int32_t rel = (int32_t)((uintptr_t)(page + P2_CR_VARC_ACTIVE_ENTRY) - (uintptr_t)(entry_site + 5));
    memcpy(detour + 1, &rel, sizeof(rel));
    detour[5] = 0x90u;
    if (!patch_bytes(entry_site, detour, sizeof(detour), NULL)) {
        for (size_t j = 0; j < n_sites; ++j) {
            uint8_t *csite = (uint8_t *)(uintptr_t)(base + kVarcWriterSites[j].call_rva);
            uint32_t expect = (uint32_t)(uintptr_t)(base + kVarcWriterSites[j].target_rva);
            restore_call_site_rel32(csite, expect);
        }
        VirtualFree(page, 0, MEM_RELEASE);
        log_msg(h, "v2p2: fn_00515ea6_varc detour patch failed; rolled back.");
        return 0;
    }

    log_msg(h, (mode == P2_VARC_VALIDATE)
        ? "v2p2: fn_00515ea6_varc Country_Recalculate SESE variant(c) installed (mode=validate, W^X sealed)."
        : "v2p2: fn_00515ea6_varc Country_Recalculate SESE variant(c) installed (mode=prod, W^X sealed).");
    return 1;
}

/* Table for generic single-site hooks (none active until P3 promotion). */
static const P2HookSpec kSpecs[] = {
    { NULL, 0u, 0u, 0u, 0u, 0u, 0 }
};

__declspec(dllexport) int __cdecl TGL_PluginInit(const TGLHost *h) {
    if (!h || h->api_version != 1u || h->struct_size < sizeof(TGLHost)) {
        return 1;
    }
    if (!verify_target_pe(h)) {
        log_msg(h, "v2p2: PE fingerprint mismatch; aborting hook install.");
        return 2;
    }

    const uint8_t *base = (const uint8_t *)h->exe_base;
    int installed = 0;
    installed += install_highperfwinclock_pilot(h, base);
    int sese_a = install_country_recalculate_sese(h, base);
    installed += sese_a;
    installed += install_country_recalculate_varc(h, base, sese_a);

    for (size_t i = 0; i < sizeof(kSpecs) / sizeof(kSpecs[0]); ++i) {
        const P2HookSpec *spec = &kSpecs[i];
        if (!spec->ini_key) {
            continue;
        }
        uint32_t mode = parse_mode_ini(h->config_file, spec->ini_key);
        if (mode == P2_MODE_OFF) {
            continue;
        }
        if (!valid_arg_bytes(spec->arg_bytes)) {
            log_msg(h, "v2p2: invalid arg_bytes; leaving site unpatched.");
            continue;
        }
        if (mode == P2_MODE_SHADOW && (spec->flags & 2u) == 0u) {
            log_msg(h, "v2p2: mode=shadow rejected (no shadow comparator registered); leaving site unpatched.");
            continue;
        }
        uint32_t orig_va = (uint32_t)(uintptr_t)(base + spec->expected_target_rva);
        void *blob = alloc_sealed_pic_blob(orig_va, spec->handler_fn, mode, spec->arg_bytes, spec->flags, (uint32_t)(uintptr_t)base);
        if (!blob) {
            log_msg(h, "v2p2: failed to allocate/seal PIC blob.");
            continue;
        }
        void *entry = (uint8_t *)blob + P2_OFF_HOOK_ENTRY;
        int ok = spec->is_vtable_slot
            ? patch_vtable_slot((uint32_t *)(uintptr_t)(base + spec->site_rva), orig_va, entry)
            : patch_call_site_rel32((uint8_t *)(uintptr_t)(base + spec->site_rva), orig_va, entry);
        if (!ok) {
            VirtualFree(blob, 0, MEM_RELEASE);
            log_msg(h, "v2p2: patch-site signature mismatch; leaving site unpatched.");
            continue;
        }
        ++installed;
    }

    char msg[128];
    snprintf(msg, sizeof(msg), "v2p2: TGL_PluginInit ready (PE verified, %d hooks installed, W^X sealed).", installed);
    log_msg(h, msg);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved) {
    (void)inst;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(inst);
    }
    return TRUE;
}
