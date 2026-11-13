"""Verify build/v2p2.dll PE structure, exports, and runtime TGL_PluginInit gates (off/shadow/prod) under Wine."""
import os
from pathlib import Path
import subprocess
import tempfile
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

LAB = Path(__file__).resolve().parent
ROOT = LAB.parent.parent
CC = ROOT / 'tools/llvm-mingw/llvm-mingw-20261104-msvcrt-ubuntu-22.04-x86_64/bin/i686-w64-mingw32-gcc'
V2P2_DLL = LAB / 'build/v2p2.dll'
CR_SESE_BIN = LAB / 'build/cr_sese.bin'
CR_SESE_VARC_BIN = LAB / 'build/cr_sese_varc.bin'
V2P2_INI = LAB / 'v2p2.ini'
BASE_EXE = ROOT / 'base-game/v2game.exe'
WINE_PREFIX = LAB / 'wine-prefix'

HOST_TEST_C = r'''
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "p2_layout.h"

typedef int (__cdecl *TGL_PluginInit_fn)(const TGLHost *);

static char g_last_log[512];

static void __cdecl test_log(const TGLHost *h, const char *msg) {
    (void)h;
    if (msg) {
        snprintf(g_last_log, sizeof(g_last_log), "%s", msg);
    }
}

static uint8_t *load_readonly_v2_sections(const wchar_t *exe_path, size_t *out_size) {
    FILE *f = _wfopen(exe_path, L"rb");
    if (!f) {
        return NULL;
    }
    uint8_t hdr[4096];
    if (fread(hdr, 1, sizeof(hdr), f) < 1024) {
        fclose(f);
        return NULL;
    }
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)hdr;
    const IMAGE_NT_HEADERS32 *nt = (const IMAGE_NT_HEADERS32 *)(hdr + dos->e_lfanew);
    size_t img_size = nt->OptionalHeader.SizeOfImage;
    uint8_t *img = (uint8_t *)VirtualAlloc(NULL, img_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!img) {
        fclose(f);
        return NULL;
    }
    memcpy(img, hdr, nt->OptionalHeader.SizeOfHeaders);

    const IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (sec[i].SizeOfRawData == 0) {
            continue;
        }
        size_t copy_sz = sec[i].SizeOfRawData;
        if (sec[i].VirtualAddress + copy_sz > img_size) {
            copy_sz = img_size - sec[i].VirtualAddress;
        }
        _fseeki64(f, (long long)sec[i].PointerToRawData, SEEK_SET);
        fread(img + sec[i].VirtualAddress, 1, copy_sz, f);
    }
    fclose(f);

    /* Apply loader-equivalent relocations to the two pilot sites so img acts as relocated exe_base */
    uint32_t pref_base = nt->OptionalHeader.ImageBase;
    uint32_t delta = (uint32_t)(uintptr_t)img - pref_base;
    uint32_t disp = 0;
    memcpy(&disp, img + 0x0067B435u, 4);
    disp += delta;
    memcpy(img + 0x0067B435u, &disp, 4);

    uint32_t slot = 0;
    memcpy(&slot, img + 0x00A43A88u, 4);
    slot += delta;
    memcpy(img + 0x00A43A88u, &slot, 4);

    /* Mark .text RX so VirtualProtect inside v2p2.dll is exercised on realistic protections */
    DWORD oldp = 0;
    VirtualProtect(img + 0x1000u, 0x00900000u, PAGE_EXECUTE_READ, &oldp);
    *out_size = img_size;
    return img;
}

static void write_ini(const wchar_t *path, const char *a7b490_mode, const char *cr_mode, const char *varc_mode) {
    FILE *f = _wfopen(path, L"wb");
    fprintf(
        f,
        "[hooks]\r\nfn_00a7b490 = %s\r\nfn_00515ea6 = %s\r\nfn_00515ea6_varc = %s\r\n",
        a7b490_mode, cr_mode, varc_mode
    );
    fclose(f);
}

static uint32_t read_rel32_target(const uint8_t *call_site) {
    int32_t rel = 0;
    memcpy(&rel, call_site + 1, sizeof(rel));
    return (uint32_t)((uintptr_t)(call_site + 5) + (intptr_t)rel);
}

static void write_e8(uint8_t *site, void *target) {
    site[0] = 0xE8u;
    int32_t rel = (int32_t)((uintptr_t)target - (uintptr_t)(site + 5));
    memcpy(site + 1, &rel, sizeof(rel));
}

static void write_e9(uint8_t *site, void *target) {
    site[0] = 0xE9u;
    int32_t rel = (int32_t)((uintptr_t)target - (uintptr_t)(site + 5));
    memcpy(site + 1, &rel, sizeof(rel));
}

typedef struct MockWorldCtx {
    uint8_t  *mock_img;
    uint8_t **entries;
    uint32_t  total_tags;
    uint8_t  *self_ptr;
    uint32_t  mgr[2];
    int32_t   last_esp18;
    int       mid_chgtag_sese_ok;
} MockWorldCtx;

static MockWorldCtx g_mock;

__attribute__((noinline))
static int32_t invoke_mock_sese(uint8_t *entry_va, void *self, void *mgr_ptr) {
    int32_t out_esp18 = -1;
    int32_t *out_ptr = &out_esp18;
    void *a_tmp = entry_va;
    void *d_tmp = self;
    void *c_tmp = mgr_ptr;
    /* Exit stub at mock_img + 0x00116286 executes original 6B then returns to 1: */
    __asm__ volatile (
        "pushl $1f\n\t"
        "pushl %%ebx\n\t"
        "pushl %%esi\n\t"
        "pushl %%edi\n\t"
        "pushl %%ebp\n\t"
        "pushl %%edi\n\t"
        "subl $0x60, %%esp\n\t"
        "movl %%ecx, 0x28(%%esp)\n\t"
        "movl $0, 0x18(%%esp)\n\t"
        "movl %%edx, %%ebx\n\t"
        "jmp *%%eax\n\t"
        "1:\n\t"
        : "+a"(a_tmp), "+d"(d_tmp), "+c"(c_tmp)
        : "D"(out_ptr)
        : "cc", "memory"
    );
    return out_esp18;
}

static void __thiscall mock_set_owner_impl(uint8_t *prov, uint32_t *new_tag, uint32_t a2, uint32_t a3, uint8_t arg4) {
    (void)a2;
    (void)a3;
    uint32_t old_id = *(uint32_t *)(prov + 0x12Cu);
    uint32_t new_id = new_tag ? new_tag[1] : 0u;
    if (arg4 == 0u) {
        if (old_id != 0u && old_id < g_mock.total_tags) {
            uint8_t *oc = g_mock.entries[old_id];
            uint32_t end = *(uint32_t *)(oc + 0x9DCu);
            if (end >= *(uint32_t *)(oc + 0x9D8u) + 4u) {
                *(uint32_t *)(oc + 0x9DCu) = end - 4u;
            }
        }
        if (new_id != 0u && new_id < g_mock.total_tags &&
            (g_mock.entries[new_id][0x1Cu] != 'R' || g_mock.entries[new_id][0x1Du] != 'E' || g_mock.entries[new_id][0x1Eu] != 'B')) {
            uint8_t *nc = g_mock.entries[new_id];
            *(uint32_t *)(nc + 0x9DCu) += 4u;
        }
    }
    *(uint32_t *)(prov + 0x12Cu) = new_id;
}

static void __stdcall mock_country_reset_impl(uint8_t *c) {
    *(uint32_t *)(c + 0x9DCu) = *(uint32_t *)(c + 0x9D8u);
}

static void __stdcall mock_world_change_tag_impl(void *world, uint32_t *tag1, uint32_t *tag2) {
    (void)world;
    uint32_t id1 = tag1[1], id2 = tag2[1];
    uint8_t *c1 = g_mock.entries[id1];
    uint8_t *c2 = g_mock.entries[id2];
    /* Simulate CCountry::ChangeTag calling SetOwner(..., arg4=1) via patched 0x000F9900 */
    typedef void (__thiscall *SetOwnerCallFn)(void *, void *, uint32_t, uint32_t, uint8_t);
    uint32_t rel_t = read_rel32_target(g_mock.mock_img + 0x000F9900u);
    uint8_t prov_dummy[0x140];
    memset(prov_dummy, 0, sizeof(prov_dummy));
    *(uint32_t *)(prov_dummy + 0x12Cu) = id1;
    ((SetOwnerCallFn)(uintptr_t)rel_t)(prov_dummy, tag2, 0u, 0u, 1u);

    /* Swap pointers & update +0x20 just like CWorld::ChangeTag 0x00688D67..0x00688D88 */
    *(uint32_t *)(c1 + 0x20u) = id2;
    *(uint32_t *)(c2 + 0x20u) = id1;
    g_mock.entries[id1] = c2;
    g_mock.entries[id2] = c1;
    /* Also call Country_Recalculate SESE mid-ChangeTag (mirroring 0x00689401!) */
    int32_t mid_18 = invoke_mock_sese(g_mock.mock_img + 0x00115EA6u, g_mock.self_ptr, g_mock.mgr);
    g_mock.mid_chgtag_sese_ok = (mid_18 == (int32_t)g_mock.total_tags);
}

int wmain(int argc, wchar_t **argv) {
    if (argc < 5) {
        fprintf(stderr, "Usage: host.exe <v2p2.dll> <v2p2.ini> <v2game.exe> <tmp_ini>\n");
        return 10;
    }
    HMODULE dll = LoadLibraryW(argv[1]);
    if (!dll) {
        fprintf(stderr, "LoadLibraryW failed: %lu\n", (unsigned long)GetLastError());
        return 11;
    }
    TGL_PluginInit_fn init_fn = (TGL_PluginInit_fn)GetProcAddress(dll, "TGL_PluginInit");
    if (!init_fn) {
        fprintf(stderr, "GetProcAddress(TGL_PluginInit) failed\n");
        return 12;
    }

    /* 1. Invalid api_version -> rc 1 */
    TGLHost bad_ver = {
        .api_version = 99u,
        .struct_size = sizeof(TGLHost),
        .plugin_name = "v2p2",
        .config_file = (const uint16_t *)argv[2],
    };
    if (init_fn(&bad_ver) != 1) {
        fprintf(stderr, "Expected rc=1 on bad api_version\n");
        return 13;
    }

    /* 2. Bad PE fingerprint -> rc 2 */
    uint8_t fake_pe[4096];
    memset(fake_pe, 0, sizeof(fake_pe));
    fake_pe[0] = 'M';
    fake_pe[1] = 'Z';
    TGLHost bad_pe = {
        .api_version = 1u,
        .struct_size = sizeof(TGLHost),
        .plugin_name = "v2p2",
        .config_file = (const uint16_t *)argv[2],
        .exe_base = fake_pe,
        .exe_size = sizeof(fake_pe),
        .log = test_log,
    };
    g_last_log[0] = '\0';
    int rc_pe = init_fn(&bad_pe);
    if (rc_pe != 2) {
        fprintf(stderr, "Expected rc=2 on bad PE fingerprint, got %d\n", rc_pe);
        return 14;
    }
    printf("bad_pe_rc=%d log=\"%s\"\n", rc_pe, g_last_log);

    /* Load read-only mapped copy of base-game/v2game.exe into memory */
    size_t img_size = 0;
    uint8_t *img = load_readonly_v2_sections(argv[3], &img_size);
    if (!img) {
        fprintf(stderr, "Failed to map v2game.exe sections in memory\n");
        return 15;
    }

    /* 3. Default v2p2.ini (fn_00a7b490 = off, fn_00515ea6 = off) -> 0 hooks installed, bytes untouched */
    uint8_t orig_ctor[6];
    memcpy(orig_ctor, img + 0x0067B433u, 6);
    uint32_t orig_slot = *(uint32_t *)(img + 0x00A43A88u);
    uint8_t orig_cr[6];
    memcpy(orig_cr, img + 0x00115EA6u, 6);

    TGLHost host_off = {
        .api_version = 1u,
        .struct_size = sizeof(TGLHost),
        .plugin_name = "v2p2",
        .config_file = (const uint16_t *)argv[2],
        .exe_base = img,
        .exe_size = img_size,
        .log = test_log,
    };
    if (init_fn(&host_off) != 0) {
        fprintf(stderr, "Expected rc=0 on default v2p2.ini\n");
        return 16;
    }
    if (memcmp(img + 0x0067B433u, orig_ctor, 6) != 0 ||
        *(uint32_t *)(img + 0x00A43A88u) != orig_slot ||
        memcmp(img + 0x00115EA6u, orig_cr, 6) != 0) {
        fprintf(stderr, "off mode modified bytes unexpectedly\n");
        return 17;
    }
    printf("off_mode_rc=0 log=\"%s\"\n", g_last_log);

    /* 4. shadow mode must be refused without comparator (both hooks) */
    write_ini(argv[4], "shadow", "shadow", "off");
    TGLHost host_tmp = host_off;
    host_tmp.config_file = (const uint16_t *)argv[4];
    if (init_fn(&host_tmp) != 0) {
        return 18;
    }
    if (memcmp(img + 0x0067B433u, orig_ctor, 6) != 0 ||
        *(uint32_t *)(img + 0x00A43A88u) != orig_slot ||
        memcmp(img + 0x00115EA6u, orig_cr, 6) != 0) {
        fprintf(stderr, "shadow mode modified bytes unexpectedly\n");
        return 19;
    }
    printf("shadow_refused_log=\"%s\"\n", g_last_log);

    /* 5. prod mode installs paired ctor skip + W^X PIC dtor vtable hook + fn_00515ea6 SESE */
    write_ini(argv[4], "prod", "prod", "off");
    if (init_fn(&host_tmp) != 0) {
        return 20;
    }
    static const uint8_t kExpectedCtorPatch[6] = { 0x83u, 0xC4u, 0x04u, 0xEBu, 0x3Eu, 0x90u };
    if (memcmp(img + 0x0067B433u, kExpectedCtorPatch, 6) != 0) {
        fprintf(stderr, "ctor skip patch bytes mismatch\n");
        return 21;
    }
    uint32_t hooked_slot = *(uint32_t *)(img + 0x00A43A88u);
    if (hooked_slot == orig_slot) {
        fprintf(stderr, "dtor vtable slot was not patched\n");
        return 22;
    }
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((LPCVOID)(uintptr_t)hooked_slot, &mbi, sizeof(mbi)) ||
        mbi.Protect != PAGE_EXECUTE_READ) {
        fprintf(stderr, "PIC blob page is not W^X PAGE_EXECUTE_READ (protect=0x%lx)\n",
                (unsigned long)mbi.Protect);
        return 23;
    }
    if (img[0x00115EA6u] != 0xE9u || img[0x00115EABu] != 0x90u) {
        fprintf(stderr, "fn_00515ea6 prod mode did not write E9+NOP detour\n");
        return 25;
    }
    int32_t cr_rel = 0;
    memcpy(&cr_rel, img + 0x00115EA7u, 4);
    uintptr_t cr_target = (uintptr_t)(img + 0x00115EA6u + 5u) + (intptr_t)cr_rel;
    MEMORY_BASIC_INFORMATION cr_mbi;
    if (!VirtualQuery((LPCVOID)cr_target, &cr_mbi, sizeof(cr_mbi)) ||
        cr_mbi.Protect != PAGE_EXECUTE_READ) {
        fprintf(stderr, "fn_00515ea6 SESE page is not W^X PAGE_EXECUTE_READ (protect=0x%lx)\n",
                (unsigned long)cr_mbi.Protect);
        return 26;
    }
    printf("prod_mode_rc=0 cr_target=0x%08lx prot=0x%lx log=\"%s\"\n",
           (unsigned long)cr_target, (unsigned long)cr_mbi.Protect, g_last_log);

    /* 6. Live Wine execution of patched vtable[0] with flags=0 */
    uint32_t fake_clock[12];
    memset(fake_clock, 0, sizeof(fake_clock));
    fake_clock[0] = (uint32_t)(uintptr_t)(img + 0x00A43A88u);
    typedef uint32_t (__thiscall *dtor_fn)(void *, uint32_t);
    dtor_fn fn = (dtor_fn)(uintptr_t)hooked_slot;
    uint32_t ret = fn(fake_clock, 0u);
    uint32_t expected_base_vtbl = (uint32_t)(uintptr_t)(img + 0x00A388A8u);
    if (ret != (uint32_t)(uintptr_t)fake_clock || fake_clock[0] != expected_base_vtbl) {
        fprintf(stderr, "Live hooked dtor mismatch: ret=0x%08x vtbl=0x%08x\n", ret, fake_clock[0]);
        return 24;
    }
    printf("live_dtor_flags0 PASS: ret==this vtable==base_vtable\n");

    /* 7. fn_00515ea6_varc = validate & prod on fresh mapped v2game.exe images */
    static const struct { uint32_t call_rva; uint32_t orig_rva; } kVarcSites[10] = {
        { 0x000A9B5Bu, 0x000B52E0u },
        { 0x000B5965u, 0x000B52E0u },
        { 0x000B5CC5u, 0x000B52E0u },
        { 0x000EC6F4u, 0x000B52E0u },
        { 0x000F9900u, 0x000B52E0u },
        { 0x00137170u, 0x000B52E0u },
        { 0x001F4020u, 0x000B52E0u },
        { 0x000F8284u, 0x00103020u },
        { 0x0027E78Au, 0x00103020u },
        { 0x00480F83u, 0x002881D0u },
    };

    const char *varc_modes[2] = { "validate", "prod" };
    for (int m_i = 0; m_i < 2; ++m_i) {
        size_t sz_v = 0;
        uint8_t *img_v = load_readonly_v2_sections(argv[3], &sz_v);
        if (!img_v) {
            fprintf(stderr, "Failed to map img_v\n");
            return 27;
        }
        /* Verify vanilla targets match before patching */
        for (int s = 0; s < 10; ++s) {
            if (img_v[kVarcSites[s].call_rva] != 0xE8u ||
                read_rel32_target(img_v + kVarcSites[s].call_rva) != (uint32_t)(uintptr_t)(img_v + kVarcSites[s].orig_rva)) {
                fprintf(stderr, "Vanilla writer call site mismatch idx=%d\n", s);
                return 28;
            }
        }
        write_ini(argv[4], "off", "off", varc_modes[m_i]);
        TGLHost host_v = host_off;
        host_v.exe_base = img_v;
        host_v.exe_size = sz_v;
        host_v.config_file = (const uint16_t *)argv[4];
        g_last_log[0] = '\0';
        if (init_fn(&host_v) != 0) {
            return 29;
        }
        if (img_v[0x00115EA6u] != 0xE9u || img_v[0x00115EABu] != 0x90u) {
            fprintf(stderr, "fn_00515ea6_varc(%s) did not write E9+NOP detour\n", varc_modes[m_i]);
            return 30;
        }
        uint32_t varc_target = read_rel32_target(img_v + 0x00115EA6u);
        MEMORY_BASIC_INFORMATION vmbi;
        if (!VirtualQuery((LPCVOID)(uintptr_t)varc_target, &vmbi, sizeof(vmbi)) ||
            vmbi.Protect != PAGE_EXECUTE_READ) {
            fprintf(stderr, "fn_00515ea6_varc(%s) page not W^X PAGE_EXECUTE_READ\n", varc_modes[m_i]);
            return 31;
        }
        uint32_t t_set_owner = read_rel32_target(img_v + kVarcSites[0].call_rva);
        uint32_t t_reset     = read_rel32_target(img_v + kVarcSites[7].call_rva);
        uint32_t t_chg_tag   = read_rel32_target(img_v + kVarcSites[9].call_rva);
        if (t_set_owner == (uint32_t)(uintptr_t)(img_v + kVarcSites[0].orig_rva) ||
            t_reset == (uint32_t)(uintptr_t)(img_v + kVarcSites[7].orig_rva) ||
            t_chg_tag == (uint32_t)(uintptr_t)(img_v + kVarcSites[9].orig_rva)) {
            fprintf(stderr, "fn_00515ea6_varc(%s) writer call sites not patched\n", varc_modes[m_i]);
            return 32;
        }
        for (int s = 0; s < 7; ++s) {
            if (read_rel32_target(img_v + kVarcSites[s].call_rva) != t_set_owner) {
                fprintf(stderr, "SetOwner site %d target mismatch\n", s);
                return 33;
            }
        }
        if (read_rel32_target(img_v + kVarcSites[8].call_rva) != t_reset) {
            fprintf(stderr, "Country::Reset site 1 target mismatch\n");
            return 34;
        }
        printf("varc_%s_rc=0 sese=0x%08x prot=0x%lx set_owner_wrap=0x%08x reset_wrap=0x%08x chgtag_wrap=0x%08x log=\"%s\"\n",
               varc_modes[m_i], varc_target, (unsigned long)vmbi.Protect, t_set_owner, t_reset, t_chg_tag, g_last_log);
        VirtualFree(img_v, 0, MEM_RELEASE);
    }

    /* 8. Live Wine runtime test of V2 writer hooks (SetOwner arg4=0/1, Reset, ChangeTag) + validate */
    {
        const size_t mock_sz = 0x00E60000u;
        uint8_t *mock_img = (uint8_t *)VirtualAlloc(NULL, mock_sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!mock_img) {
            return 35;
        }
        memcpy(mock_img, img, 4096u);
        /* SESE entry & exit signatures; exit appends frame restore matching invoke_mock_sese */
        static const uint8_t kSeseEntry[6] = { 0x8Bu, 0x54u, 0x24u, 0x28u, 0x8Bu, 0x02u };
        static const uint8_t kExitStub[24] = {
            0x8Bu, 0x83u, 0x00u, 0x0Au, 0x00u, 0x00u,
            0x8Bu, 0x44u, 0x24u, 0x18u,
            0x8Bu, 0x4Cu, 0x24u, 0x60u,
            0x89u, 0x01u,
            0x83u, 0xC4u, 0x64u,
            0x5Du, 0x5Fu, 0x5Eu, 0x5Bu, 0xC3u
        };
        memcpy(mock_img + 0x00115EA6u, kSeseEntry, sizeof(kSeseEntry));
        memcpy(mock_img + 0x00116286u, kExitStub, sizeof(kExitStub));

        /* Stub 0x000A8300 (xor eax,eax; ret) and 0x00111140 (xor eax,eax; ret 4) */
        mock_img[0x000A8300u + 0] = 0x31u; mock_img[0x000A8300u + 1] = 0xC0u; mock_img[0x000A8300u + 2] = 0xC3u;
        mock_img[0x00111140u + 0] = 0x31u; mock_img[0x00111140u + 1] = 0xC0u;
        mock_img[0x00111140u + 2] = 0xC2u; mock_img[0x00111140u + 3] = 0x04u; mock_img[0x00111140u + 4] = 0x00u;

        /* Wire all 10 writer E8 call sites + target E9 stubs */
        for (int s = 0; s < 10; ++s) {
            write_e8(mock_img + kVarcSites[s].call_rva, mock_img + kVarcSites[s].orig_rva);
        }
        write_e9(mock_img + 0x000B52E0u, (void *)&mock_set_owner_impl);
        write_e9(mock_img + 0x00103020u, (void *)&mock_country_reset_impl);
        write_e9(mock_img + 0x002881D0u, (void *)&mock_world_change_tag_impl);

        /* Set up 8 countries, relations, world, and country_mgr */
        uint8_t *countries_buf = (uint8_t *)VirtualAlloc(NULL, 8u * 0x1800u, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        uint8_t *rels_buf = (uint8_t *)VirtualAlloc(NULL, 8u * 0x100u, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        uint8_t **entries_arr = (uint8_t **)VirtualAlloc(NULL, 8u * sizeof(uint8_t *), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        uint8_t **rel_ptrs = (uint8_t **)VirtualAlloc(NULL, 8u * sizeof(uint8_t *), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        uint8_t *world_buf = (uint8_t *)VirtualAlloc(NULL, 4096u, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        static const char *kTagNames[8] = { "NON", "SPA", "REB", "PRU", "NGF", "FRA", "ENG", "AUS" };
        for (uint32_t i = 0; i < 8u; ++i) {
            uint8_t *c = countries_buf + i * 0x1800u;
            entries_arr[i] = c;
            memcpy(c + 0x1Cu, kTagNames[i], 4);
            *(uint32_t *)(c + 0x20u) = i;
            *(uint32_t *)(c + 0x9D8u) = 0x1000u;
            /* Start: SPA(1)=1 prov, PRU(3)=1 prov, NGF(4)=0 prov, FRA(5)=1 prov */
            uint32_t psz = (i == 1u || i == 3u || i == 5u) ? 4u : 0u;
            *(uint32_t *)(c + 0x9DCu) = 0x1000u + psz;
            rel_ptrs[i] = rels_buf + i * 0x100u;
        }
        uint8_t *self_c = entries_arr[1];
        *(uint8_t ***)(self_c + 0xBE8u) = rel_ptrs;
        *(uint32_t *)(self_c + 0x142Cu) = 0xFFFFFFFFu;
        g_mock.mock_img = mock_img;
        g_mock.entries = entries_arr;
        g_mock.total_tags = 8u;
        g_mock.self_ptr = self_c;
        g_mock.mgr[0] = 8u;
        g_mock.mgr[1] = (uint32_t)(uintptr_t)entries_arr;
        *(uint32_t **)(mock_img + 0x00E587E4u) = g_mock.mgr;
        *(uint8_t **)(mock_img + 0x00E588E8u) = world_buf;

        /* Remove any prior validate log in tmp_dir */
        wchar_t val_log[MAX_PATH];
        wcscpy(val_log, argv[4]);
        wchar_t *sep = wcsrchr(val_log, L'\\');
        if (!sep) sep = wcsrchr(val_log, L'/');
        if (sep) wcscpy(sep + 1, L"v2p2_varc_validate.log");
        else wcscpy(val_log, L"v2p2_varc_validate.log");
        DeleteFileW(val_log);

        write_ini(argv[4], "off", "off", "validate");
        TGLHost host_live = host_off;
        host_live.exe_base = mock_img;
        host_live.exe_size = mock_sz;
        host_live.config_file = (const uint16_t *)argv[4];
        if (init_fn(&host_live) != 0) {
            return 36;
        }

        /* Step A: initial lazy-init SESE */
        if (invoke_mock_sese(mock_img + 0x00115EA6u, self_c, g_mock.mgr) != 8) return 37;

        /* Step B: colonization/transfer via patched SetOwner(0x000B5965, arg4=0): NGF(4) gains 1 prov, PRU(3) loses last -> dead */
        typedef void (__thiscall *SetOwnerFn)(void *, void *, uint32_t, uint32_t, uint8_t);
        uint32_t wrap_set_owner = read_rel32_target(mock_img + 0x000B5965u);
        uint8_t prov0[0x140];
        memset(prov0, 0, sizeof(prov0));
        *(uint32_t *)(prov0 + 0x12Cu) = 3u;
        uint32_t tag_ngf[2] = { 0u, 4u };
        ((SetOwnerFn)(uintptr_t)wrap_set_owner)(prov0, tag_ngf, 0u, 0u, 0u);
        if (invoke_mock_sese(mock_img + 0x00115EA6u, self_c, g_mock.mgr) != 8) return 38;

        /* Step C: CWorld::ChangeTag(0x00480F83): swap NGF(4, live) <-> ENG(6, dead), including mid-call SESE! */
        typedef void (__stdcall *ChangeTagFn)(void *, uint32_t *, uint32_t *);
        uint32_t wrap_chg = read_rel32_target(mock_img + 0x00480F83u);
        uint32_t tag_eng[2] = { 0u, 6u };
        ((ChangeTagFn)(uintptr_t)wrap_chg)(world_buf, tag_ngf, tag_eng);
        if (!g_mock.mid_chgtag_sese_ok) {
            fprintf(stderr, "Mid-ChangeTag SESE failed\n");
            return 39;
        }
        if (invoke_mock_sese(mock_img + 0x00115EA6u, self_c, g_mock.mgr) != 8) return 40;

        /* Step D: CCountry::Reset(0x0027E78A) clears FRA(5) */
        typedef void (__stdcall *ResetFn)(void *);
        uint32_t wrap_rst = read_rel32_target(mock_img + 0x0027E78Au);
        ((ResetFn)(uintptr_t)wrap_rst)(entries_arr[5]);
        if (invoke_mock_sese(mock_img + 0x00115EA6u, self_c, g_mock.mgr) != 8) return 41;

        /* Confirm 0 mismatches occurred during all legitimate transitions */
        if (GetFileAttributesW(val_log) != INVALID_FILE_ATTRIBUTES) {
            fprintf(stderr, "Unexpected validate mismatch during clean writer transitions!\n");
            return 42;
        }

        /* Step E: Negative control — raw unhooked write to entries[3]+0x9DC MUST be caught by validate! */
        *(uint32_t *)(entries_arr[3] + 0x9DCu) = 0x1008u;
        if (invoke_mock_sese(mock_img + 0x00115EA6u, self_c, g_mock.mgr) != 8) return 43;
        FILE *lf = _wfopen(val_log, L"rb");
        if (!lf) {
            fprintf(stderr, "validate negative control did not write v2p2_varc_validate.log\n");
            return 44;
        }
        char lbuf[256];
        memset(lbuf, 0, sizeof(lbuf));
        fread(lbuf, 1, sizeof(lbuf) - 1, lf);
        fclose(lf);
        if (!strstr(lbuf, "idx=3 expected=1 actual=0")) {
            fprintf(stderr, "validate log unexpected content: %s\n", lbuf);
            return 45;
        }
        printf("live_varc_writers_and_validate PASS: zero_mismatch_transitions + neg_ctrl=\"%s\"\n", lbuf);
        DeleteFileW(val_log);
        VirtualFree(world_buf, 0, MEM_RELEASE);
        VirtualFree(rel_ptrs, 0, MEM_RELEASE);
        VirtualFree(entries_arr, 0, MEM_RELEASE);
        VirtualFree(rels_buf, 0, MEM_RELEASE);
        VirtualFree(countries_buf, 0, MEM_RELEASE);
        VirtualFree(mock_img, 0, MEM_RELEASE);
    }

    VirtualFree(img, 0, MEM_RELEASE);
    FreeLibrary(dll);
    return 0;
}
'''


def main() -> None:
    if not V2P2_DLL.exists():
        raise RuntimeError(f'Missing {V2P2_DLL}; build v2p2.dll first.')

    pe = pefile.PE(str(V2P2_DLL), fast_load=False)
    assert pe.FILE_HEADER.Machine == 0x014C, f'Unexpected machine {pe.FILE_HEADER.Machine:#x}'
    dll_chars = pe.OPTIONAL_HEADER.DllCharacteristics
    assert dll_chars & 0x0040, 'Missing DYNAMIC_BASE'
    assert dll_chars & 0x0100, 'Missing NX_COMPAT'
    exports = [e.name.decode() for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name]
    assert exports == ['TGL_PluginInit'], f'Unexpected exports: {exports}'
    assert CR_SESE_BIN.exists(), f'Missing {CR_SESE_BIN}'
    assert CR_SESE_VARC_BIN.exists(), f'Missing {CR_SESE_VARC_BIN}'
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    rdtsc_hits = [i.address for i in cs.disasm(CR_SESE_BIN.read_bytes(), 0) if i.mnemonic == 'rdtsc']
    assert not rdtsc_hits, f'Unexpected rdtsc in prod cr_sese.bin: {rdtsc_hits}'
    varc_insns = list(cs.disasm(CR_SESE_VARC_BIN.read_bytes(), 0))
    assert not any(i.mnemonic == 'rdtsc' for i in varc_insns), 'Unexpected rdtsc in cr_sese_varc.bin'
    assert not any(i.mnemonic == 'prefetcht0' for i in varc_insns), 'Unexpected prefetcht0 in cr_sese_varc.bin'
    assert any(i.mnemonic == 'bsf' for i in varc_insns), 'Missing bsf in cr_sese_varc.bin'
    print(f'PE check PASS: i386 DLL, DYNAMIC_BASE+NX_COMPAT, exports={exports}, prod_cr_rdtsc=0, varc_bsf=yes')

    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        src = tmp_dir / 'host_test.c'
        exe = tmp_dir / 'host_test.exe'
        tmp_ini = tmp_dir / 'tmp_v2p2.ini'
        src.write_text(HOST_TEST_C)
        subprocess.run([
            str(CC), '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-municode',
            f'-I{LAB}', str(src), '-o', str(exe),
        ], check=True)

        env = os.environ.copy()
        env['WINEPREFIX'] = str(WINE_PREFIX)
        env['WINEDEBUG'] = '-all'
        env.pop('WINEARCH', None)
        proc = subprocess.run(
            ['wine', str(exe), str(V2P2_DLL), str(V2P2_INI), str(BASE_EXE), str(tmp_ini)],
            env=env, capture_output=True, text=True, check=True,
        )
        print(proc.stdout.strip())
    print('v2p2.dll integration PASS: 12/12 host, HighPerfWinClock, fn_00515ea6 & fn_00515ea6_varc (incl. live writers+validate) checks verified')


if __name__ == '__main__':
    main()
