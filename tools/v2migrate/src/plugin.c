/* v2migrate: layout-A prototype behind an ini switch (default: observe only).
 *
 * Design (v2): instead of a post-load bulk migration, the single relation
 * allocation site (push 0xAC / call operator new at 0x005047F7, the only
 * caller of the relation constructor) is redirected to a bump allocator
 * over one preallocated block. The constructor, the vector push_back, and
 * all readers then work unchanged with block pointers; later growth (new
 * nations) is covered automatically. Fallback to the original operator new
 * if the block ever exhausts (logged).
 *
 * A tick hook (call to the daily tick at 0x00683AB1) only observes: on the
 * first tick it logs country/relation counts.
 *
 * Safety basis (research/perf/experiments/relations-soa/README.md):
 * - single new(0xAC)+ctor path; objects never freed individually (no delete
 *   near any BE8/BEC/BF0 use in .text; country dtor ignores the vector);
 * - vector growth copies pointers only, readers reload the base per access;
 * - no child-to-relation back-pointer found; stack-temp copies transient.
 * Originals never exist under migrate=1 (constructed in place), so there is
 * nothing to free and no double-ownership. Live matrix at 1837.1.1 is
 * 272x272, growing on demand; the block is sized for the full 683x683.
 *
 * Slot stride is 176 (0xAC rounded up) so every slot stays 8-aligned like
 * operator-new results. Bump uses InterlockedExchangeAdd (creation is
 * single-threaded today; this is free insurance).
 *
 * Addresses over v2game.exe 3.04 (SHA-256 62d48c20...), base 0x00400000.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

typedef struct Host {
    uint32_t api_version, struct_size;
    const char *plugin_name;
    const wchar_t *game_dir, *config_file, *plugin_dir;
    void *exe_base;
    size_t exe_size;
    void (*log)(const struct Host *, const char *);
} Host;

static const Host *host_api;
static uintptr_t image;
static uint32_t migrate_on;
static int counted;

/* Originals; stubs jmp/call through these pointers. */
uintptr_t migrate_orig_tick;
uintptr_t migrate_orig_new;

/* Bump block: 683 x 683 slots of 176 bytes. */
#define TAG_N 683u
#define REL_SIZE 0xACu
#define SLOT_SIZE 176u
#define BLOCK_SLOTS ((size_t)TAG_N * (size_t)TAG_N)
static unsigned char *block_base;
static size_t block_end;
static volatile LONG block_bump;
static uint32_t fallback_calls;

#define RVA(va) ((uint32_t)(va) - 0x00400000u)

static void note(const char *s) { host_api->log(host_api, s); }
static void note_fmt(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    buf[sizeof(buf) - 1] = 0;
    note(buf);
}

static uint32_t rd(uintptr_t p) { return *(const uint32_t *)p; }

/* Bump allocator for 0xAC relation objects. Returns 0 to fall back. */
uintptr_t migrate_bump_alloc(uint32_t size) {
    size_t off;
    if (size != REL_SIZE || !block_base) return 0;
    off = (size_t)InterlockedExchangeAdd(&block_bump, (LONG)SLOT_SIZE);
    if (off + SLOT_SIZE > block_end) {
        fallback_calls++;
        return 0;
    }
    return (uintptr_t)(block_base + off);
}

/* Called once from the tick stub on the first daily tick: observe only. */
void migrate_note_tick(void) {
    uintptr_t vec;
    uint32_t cbegin, cend, ncountries;
    uint64_t total_objs;
    uint32_t i;

    if (counted) return;
    counted = 1;
    vec = rd(image + RVA(0x12587e4));
    if (!vec) {
        note("[migrate] no countries vector");
        return;
    }
    cbegin = rd(vec + 4);
    cend = rd(vec + 8);
    if (cend <= cbegin || (cend - cbegin) > 2048u * 4u ||
        ((cend - cbegin) & 3u)) {
        note("[migrate] bad countries vector");
        return;
    }
    ncountries = (cend - cbegin) / 4u;
    total_objs = 0;
    for (i = 0; i < ncountries; i++) {
        uintptr_t country = rd((uintptr_t)cbegin + (uintptr_t)i * 4u);
        uintptr_t begin, end;
        if (!country) continue;
        begin = rd(country + 0xBE8);
        end = rd(country + 0xBEC);
        if (end > begin)
            total_objs += (uint64_t)((end - begin) / 4u);
    }
    note_fmt("[migrate] countries=%u relations=%llu",
             ncountries, (unsigned long long)total_objs);
}

static int redirect(uint32_t site, uint32_t target, uintptr_t replacement) {
    unsigned char *p = (unsigned char *)(image + site);
    int32_t old_rel, new_rel;
    DWORD old, unused;
    if (host_api->exe_size < 5 || site > host_api->exe_size - 5 ||
        target >= host_api->exe_size || p[0] != 0xe8) return 0;
    memcpy(&old_rel, p + 1, 4);
    if ((uintptr_t)(p + 5) + old_rel != image + target) return 0;
    new_rel = (int32_t)(replacement - (uintptr_t)(p + 5));
    if (!VirtualProtect(p, 5, PAGE_EXECUTE_READWRITE, &old)) return 0;
    memcpy(p + 1, &new_rel, 4);
    VirtualProtect(p, 5, old, &unused);
    FlushInstructionCache(GetCurrentProcess(), p, 5);
    return 1;
}

void migrate_tick_entry(void);
void migrate_new_entry(void);

__declspec(dllexport) int __cdecl TGL_PluginInit(const Host *h) {
    if (!h || h->api_version != 1 || h->struct_size < sizeof(Host) || sizeof(void *) != 4) return 1;
    host_api = h; image = (uintptr_t)h->exe_base;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)image;
    IMAGE_NT_HEADERS32 *pe = (IMAGE_NT_HEADERS32 *)(image + dos->e_lfanew);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || pe->Signature != IMAGE_NT_SIGNATURE ||
        pe->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 ||
        pe->OptionalHeader.SizeOfImage != 0x01092000 || h->exe_size != 0x01092000) return 2;

    migrate_on = GetPrivateProfileIntW(L"v2migrate", L"migrate", 0, h->config_file);
    migrate_orig_tick = image + RVA(0x6859c0);
    migrate_orig_new = image + RVA(0xaae9af);

    if (migrate_on) {
        block_base = HeapAlloc(GetProcessHeap(), 0, BLOCK_SLOTS * SLOT_SIZE);
        if (block_base) {
            block_end = BLOCK_SLOTS * SLOT_SIZE;
            block_bump = 0;
        } else {
            note("[migrate] block alloc failed; new-site hook off");
        }
    }

    {
        int tick = redirect(RVA(0x683ab1), RVA(0x6859c0),
                            (uintptr_t)migrate_tick_entry);
        int news = 0;
        if (migrate_on && block_base)
            news = redirect(RVA(0x5047f7), RVA(0xaae9af),
                            (uintptr_t)migrate_new_entry);
        note_fmt("[migrate] v2migrate: tick_hook=%d new_hook=%d migrate=%u",
                 tick, news, migrate_on);
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved) {
    (void)module; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(module);
    return TRUE;
}
