#ifndef P2_LAYOUT_H
#define P2_LAYOUT_H

/* HookConfig offsets (embedded inside .text at _p2_hook_config, 32 bytes) */
#define CFG_ORIG_TARGET   0x00  /* uint32_t: original function VA / target */
#define CFG_HANDLER_FN    0x04  /* uint32_t: optional C handler fn ptr (0 = none) */
#define CFG_MODE          0x08  /* uint32_t: 0=off, 1=prod, 2=shadow */
#define CFG_ARG_BYTES     0x0C  /* uint32_t: callee-cleaned stack arg bytes (0, 4, 8, 12) */
#define CFG_FLAGS         0x10  /* uint32_t: bit0=1 -> handled when handler_fn==0; bit1=1 -> shadow comparator registered */
#define CFG_TLS_SLOT      0x14  /* uint32_t: TLS slot index (0xFFFFFFFF if unused) */
#define CFG_USER_DATA     0x18  /* uint32_t: immutable read-only user pointer */
#define CFG_RESERVED      0x1C  /* uint32_t: reserved (0) */
#define CFG_SIZE          0x20  /* 32 bytes total */

/* Country_Recalculate SESE (0x00515EA6 -> 0x00516286) PIC config (28 bytes) */
#define CFG_CR_EXE_BASE      0x00  /* uint32_t: relocated v2game.exe base VA */
#define CFG_CR_EXIT_VA       0x04  /* uint32_t: exe_base + 0x00116286 */
#define CFG_CR_BENCH_CB      0x08  /* uint32_t: optional bench callback (0 in prod) */
#define CFG_CR_BENCH_CTX     0x0C  /* uint32_t: optional bench context ptr (0 in prod) */
#define CFG_CR_VARC_STATE    0x10  /* uint32_t: pointer to CRVarCState (0 for var a) */
#define CFG_CR_VARC_MODE     0x14  /* uint32_t: 0=off, 1=validate, 2=prod */
#define CFG_CR_VARC_SYNC_FN  0x18  /* uint32_t: reserved (0 = in-blob PIC sync/validate) */
#define CFG_CR_SIZE          0x1C

#define P2_VARC_OFF          0u
#define P2_VARC_VALIDATE     1u
#define P2_VARC_PROD         2u
#define P2_VARC_MAX_TAGS  4096u
#define P2_VARC_WORDS      128u

/* Hook modes */
#define P2_MODE_OFF       0u
#define P2_MODE_PROD      1u
#define P2_MODE_SHADOW    2u

/* Handler return actions */
#define P2_ACT_FALLBACK   0
#define P2_ACT_HANDLED    1

/* SavedState layout anchored at %ebp inside _p2_hook_entry:
 *   [ebp + 0x00] = eflags
 *   [ebp + 0x04] = edi
 *   [ebp + 0x08] = esi
 *   [ebp + 0x0C] = ebp_saved
 *   [ebp + 0x10] = esp_pre
 *   [ebp + 0x14] = ebx
 *   [ebp + 0x18] = edx
 *   [ebp + 0x1C] = ecx
 *   [ebp + 0x20] = eax
 *   [ebp + 0x24] = trampoline_slot (reserved by pushl $0 before pushal)
 *   [ebp + 0x28] = caller_retaddr
 *   [ebp + 0x2C] = args[0] ...
 */
#define SS_EFLAGS         0x00
#define SS_EDI            0x04
#define SS_ESI            0x08
#define SS_EBP            0x0C
#define SS_ESP_PRE        0x10
#define SS_EBX            0x14
#define SS_EDX            0x18
#define SS_ECX            0x1C
#define SS_EAX            0x20
#define SS_SLOT           0x24
#define SS_RETADDR        0x28
#define SS_ARGS           0x2C

#ifndef __ASSEMBLER__
#include <stddef.h>
#include <stdint.h>

typedef struct P2HookConfig {
    uint32_t original_target;
    uint32_t handler_fn;
    uint32_t mode;
    uint32_t arg_bytes;
    uint32_t flags;
    uint32_t tls_slot;
    uint32_t user_data;
    uint32_t reserved;
} P2HookConfig;

typedef struct P2SavedState {
    uint32_t eflags;
    uint32_t edi;
    uint32_t esi;
    uint32_t ebp;
    uint32_t esp_pre;
    uint32_t ebx;
    uint32_t edx;
    uint32_t ecx;
    uint32_t eax;
    uint32_t slot;
    uint32_t retaddr;
    uint32_t args[1];
} P2SavedState;

typedef struct __attribute__((aligned(16))) P2FxSave {
    uint16_t fcw;
    uint16_t fsw;
    uint8_t  ftw;
    uint8_t  rsvd1;
    uint16_t fop;
    uint32_t fip;
    uint16_t fcs;
    uint16_t rsvd2;
    uint32_t fdp;
    uint16_t fds;
    uint16_t rsvd3;
    uint32_t mxcsr;
    uint32_t mxcsr_mask;
    uint8_t  st[8][16];
    uint8_t  xmm[8][16];
    uint8_t  padding[224];
} P2FxSave;

typedef int (__cdecl *P2HandlerFn)(P2SavedState *regs, P2FxSave *fx, const P2HookConfig *cfg);

typedef struct P2CrConfig {
    uint32_t exe_base;
    uint32_t exit_va;
    uint32_t bench_cb;
    uint32_t bench_ctx;
    uint32_t varc_state;
    uint32_t varc_mode;
    uint32_t varc_sync_fn;
} P2CrConfig;

typedef struct CRVarCState {
    uint32_t alive_bits[P2_VARC_WORDS]; /* 512 B bitmask for up to 4096 tags */
    uint32_t initialized;
    uint32_t dirty;
    uint32_t total_tags;
    uint32_t entries_ptr;
    uint32_t exe_base;
    uint32_t validate_mode;
    uint32_t mismatch_count;
    uint32_t last_mismatch_idx;
    uint32_t last_expected;
    uint32_t last_actual;
    uint32_t mismatch_cb; /* void __cdecl cb(uint32_t idx, uint32_t exp, uint32_t act, uint32_t count) */
} CRVarCState;

/* The Grand Loader (dinput8.dll 1.0.0) Host struct */
typedef struct TGLHost {
    uint32_t api_version;
    uint32_t struct_size;
    const char *plugin_name;
    const uint16_t *game_dir;
    const uint16_t *config_file;
    const uint16_t *plugin_dir;
    void *exe_base;
    size_t exe_size;
    void (*log)(const struct TGLHost *, const char *);
} TGLHost;

#endif /* !__ASSEMBLER__ */
#endif /* P2_LAYOUT_H */
