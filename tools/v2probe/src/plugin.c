/* v2probe: plugin TGL de sólo lectura para resolver preguntas abiertas del bloque de IA.
 * Los stubs de src/hooks.S registran y saltan al original: no cambian pila ni retorno.
 * Direcciones sobre v2game.exe 3.04 (SHA-256 62d48c20...), base preferida 0x00400000.
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
static uint32_t probe_mask;
static uint32_t max_countries = 40;
static uint32_t seen_countries[256];
static int seen_n;
static uint32_t calls_decision, calls_820df0, calls_81e280, calls_81e5b0, calls_throttle;

/* Direcciones originales; los stubs hacen jmp a traves de estos punteros. */
uintptr_t probe_orig_decision;
uintptr_t probe_orig_820df0;
uintptr_t probe_orig_81e280;
uintptr_t probe_orig_81e5b0;
uintptr_t probe_orig_throttle;

#define RVA(va) ((uint32_t)(va) - 0x00400000u)
static uint32_t rd(uintptr_t p) { return *(const uint32_t *)p; }
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

/* devuelve el pais a partir del nodo de IA (identidad en +0x30/+0x34) */
static uintptr_t country_of(uintptr_t node) {
    if (!node) return 0;
    uint32_t idx = rd(node + 0x34);
    uintptr_t countries = rd(image + RVA(0x12587e4));
    if (!countries) return 0;
    uint32_t begin = rd(countries + 4), end = rd(countries + 8);
    if (!begin || begin >= end || idx > (end - begin) / 4) return 0;
    return rd(begin + idx * 4);
}

/* RTTI de MSVC x86: vtable[-1] -> CompleteObjectLocator; COL+0x0C -> TypeDescriptor;
 * TypeDescriptor+8 -> nombre decorado. Devuelve 0 si no hay cadena legible. */
static const char *rtti_name(uintptr_t obj) {
    if (!obj) return 0;
    uintptr_t vt = rd(obj);
    if (vt < 0x00400000 || vt > 0x02000000) return 0;
    uintptr_t col = rd(vt - 4);
    if (col < 0x00400000 || col > 0x02000000) return 0;
    uintptr_t td = rd(col + 0x0c);
    if (td < 0x00400000 || td > 0x02000000) return 0;
    const char *name = (const char *)(td + 8);
    if ((uintptr_t)name < 0x00400000 || (uintptr_t)name > 0x02000000) return 0;
    for (int i = 0; i < 96; ++i) {
        unsigned char c = (unsigned char)name[i];
        if (c == 0) return i > 3 ? name : 0;
        if (c < 32 || c > 126) return 0;
    }
    return 0;
}

static int first_time(uintptr_t country) {
    for (int i = 0; i < seen_n; ++i)
        if (seen_countries[i] == (uint32_t)country) return 0;
    if (seen_n >= (int)max_countries) return 0;
    seen_countries[seen_n++] = (uint32_t)country;
    return 1;
}

static void dump_country(uintptr_t node) {
    uintptr_t country = country_of(node);
    if (!country || !first_time(country)) return;
    uint32_t idx = rd(node + 0x34);
    uintptr_t list = rd(country + 0x7b4);
    uint32_t nodes = 0; uintptr_t n = list;
    while (n && nodes < 4) { ++nodes; n = rd(n + 8); }
    const char *t_e64 = rtti_name(rd(country + 0xe64));
    const char *t_bcc = rtti_name(rd(country + 0xbcc));
    const char *t_a60 = rtti_name(rd(country + 0xa60));
    const char *t_ce4 = rtti_name(rd(country + 0xce4));
    note_fmt("[probe] pais idx=%u c=%08x lista7b4=%08x nodos=%u tail=%08x cnt=%u flag=%u "
             "e64=%08x(%s) bcc=%08x(%s) a60=%08x(%s) ce4=%08x(%s) prov_vec=%08x/%08x",
             idx, (unsigned)country, (unsigned)list, nodes, rd(country + 0x7b8),
             rd(country + 0x7bc), (unsigned)*(unsigned char *)(country + 0x7c0),
             rd(country + 0xe64), t_e64 ? t_e64 : "-",
             rd(country + 0xbcc), t_bcc ? t_bcc : "-",
             rd(country + 0xa60), t_a60 ? t_a60 : "-",
             rd(country + 0xce4), t_ce4 ? t_ce4 : "-",
             rd(country + 0x9d8), rd(country + 0x9dc));
    if (list) {
        note_fmt("[probe]   nodo0=%08x elem=%08x c38=%08x c8c=%08x c90=%08x c94=%08x c98=%08x "
                 "cE8=%08x cEC=%08x cA0=%08x",
                 (unsigned)list, rd(list), rd(list + 0x38), rd(list + 0x8c), rd(list + 0x90),
                 rd(list + 0x94), rd(list + 0x98), rd(list + 0xe8), rd(list + 0xec), rd(list + 0xa0));
        const char *ne = rtti_name(rd(list));
        const char *na = rtti_name(rd(list + 0xa0));
        note_fmt("[probe]   tipo(elem)=%s tipo(cA0)=%s", ne ? ne : "-", na ? na : "-");
    }
    uint32_t pb = rd(country + 0x9d8), pe = rd(country + 0x9dc);
    uintptr_t pm = rd(image + RVA(0x12588e8));
    if (pb && pe > pb && pm) {
        uintptr_t table = rd(pm + 0xacc);
        uint32_t nprov = (pe - pb) / 4;
        note_fmt("[probe]   provincias=%u tabla_acc=%08x", nprov, (unsigned)table);
        for (uint32_t i = 0; i < nprov && i < 3; ++i) {
            uint32_t pid = rd(pb + i * 4);
            uintptr_t prov = (table && pid < 0x4000) ? rd(table + pid * 4) : 0;
            uintptr_t f188 = prov ? rd(prov + 0x188) : 0;
            const char *n188 = f188 ? rtti_name(f188) : 0;
            note_fmt("[probe]     id=%u prov=%08x f188=%08x f18c=%08x f384=%08x t188=%s",
                     pid, (unsigned)prov, (unsigned)f188, prov ? rd(prov + 0x18c) : 0,
                     prov ? rd(prov + 0x384) : 0, n188 ? n188 : "-");
        }
    }
}

/* llamados desde los stubs; firma cdecl */
void probe_note_decision(uintptr_t node) {
    ++calls_decision;
    if (calls_decision <= 3 || calls_decision % 2000 == 0)
        note_fmt("[probe] decision #%u node=%08x", calls_decision, (unsigned)node);
    dump_country(node);
}
void probe_note_820df0(uintptr_t node) {
    ++calls_820df0;
    if (calls_820df0 <= 2) note_fmt("[probe] 820df0 #%u node=%08x", calls_820df0, (unsigned)node);
    dump_country(node);
}
void probe_note_81e280(uintptr_t node) {
    ++calls_81e280;
    if (calls_81e280 <= 2) note_fmt("[probe] 81e280 #%u node=%08x", calls_81e280, (unsigned)node);
}
void probe_note_81e5b0(uintptr_t node) {
    ++calls_81e5b0;
    if (calls_81e5b0 <= 2) note_fmt("[probe] 81e5b0 #%u node=%08x", calls_81e5b0, (unsigned)node);
}
void probe_note_throttle(uintptr_t arg) {
    ++calls_throttle;
    if (calls_throttle <= 3 || calls_throttle % 500 == 0)
        note_fmt("[probe] throttle #%u arg=%08x", calls_throttle, (unsigned)arg);
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

void probe_decision_entry(void);
void probe_820df0_entry(void);
void probe_81e280_entry(void);
void probe_81e5b0_entry(void);
void probe_throttle_entry(void);

__declspec(dllexport) int __cdecl TGL_PluginInit(const Host *h) {
    if (!h || h->api_version != 1 || h->struct_size < sizeof(Host) || sizeof(void *) != 4) return 1;
    host_api = h; image = (uintptr_t)h->exe_base;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)image;
    IMAGE_NT_HEADERS32 *pe = (IMAGE_NT_HEADERS32 *)(image + dos->e_lfanew);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || pe->Signature != IMAGE_NT_SIGNATURE ||
        pe->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 ||
        pe->OptionalHeader.SizeOfImage != 0x01092000 || h->exe_size != 0x01092000) return 2;

    probe_mask = GetPrivateProfileIntW(L"v2probe", L"probe", 0xff, h->config_file);
    max_countries = GetPrivateProfileIntW(L"v2probe", L"max_countries", 40, h->config_file);
    if (max_countries > 256) max_countries = 256;

    probe_orig_decision = image + RVA(0x821190);
    probe_orig_820df0 = image + RVA(0x820df0);
    probe_orig_81e280 = image + RVA(0x81e280);
    probe_orig_81e5b0 = image + RVA(0x81e5b0);
    probe_orig_throttle = image + RVA(0x685620);

    int ok = 0;
    if (probe_mask & 0x01) ok += redirect(RVA(0x81ea9b), RVA(0x821190), (uintptr_t)probe_decision_entry);
    if (probe_mask & 0x02) ok += redirect(RVA(0x81ea58), RVA(0x820df0), (uintptr_t)probe_820df0_entry);
    if (probe_mask & 0x04) ok += redirect(RVA(0x81ea8e), RVA(0x81e5b0), (uintptr_t)probe_81e5b0_entry);
    if (probe_mask & 0x08) ok += redirect(RVA(0x81ea94), RVA(0x81e280), (uintptr_t)probe_81e280_entry);
    if (probe_mask & 0x10) ok += redirect(RVA(0x685b64), RVA(0x685620), (uintptr_t)probe_throttle_entry);

    note_fmt("[probe] v2probe: hooks=%d mask=%02x max=%u", ok, probe_mask, max_countries);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(module);
    return TRUE;
}
