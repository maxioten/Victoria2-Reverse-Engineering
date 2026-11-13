#include "p2_layout.h"

/* RVAs relative to v2game.exe ImageBase (0x00400000) verified against COUNTRY-RECALCULATE.md */
#define RVA_GLOBAL_WORLD        0x00E588E8u  /* VA 0x012588E8 */
#define RVA_GLOBAL_COUNTRY_MGR  0x00E587E4u  /* VA 0x012587E4 */
#define RVA_CONST_250_5F        0x00A45A40u  /* VA 0x00E45A40 (float 250.5f) */

#define RVA_FN_004A8300         0x000A8300u  /* eax=self -> al */
#define RVA_FN_004D61D0         0x000D61D0u  /* eax=&pair(8B), edi=vec* */
#define RVA_FN_004E9B90         0x000E9B90u  /* eax=&ptr(4B), edi=vec* */
#define RVA_FN_004A7BC0         0x000A7BC0u  /* esi=list*, [esp+4]=ptr, ret 4 */
#define RVA_FN_005F2AE0         0x001F2AE0u  /* esi=list*, [esp+4]=node*, ret 4 */
#define RVA_FN_00511140         0x00111140u  /* edx=&self->tag, [esp+4]=other*, ret 4 -> al */
#define RVA_FN_009692C0         0x005692C0u  /* eax=elem+0x1A8 -> eax */
#define RVA_FN_005163C0         0x001163C0u  /* eax=buf -> eax */
#define RVA_FN_OP_NEW           0x006AE9AFu  /* VA 0x00AAE9AF __cdecl(size_t) */
#define RVA_FN_ROUND            0x00001000u  /* VA 0x00401000 [esp]=float -> ST(0) */
#define RVA_FN_FTOL2_SSE        0x00731C00u  /* VA 0x00B31C00 ST(0) -> eax */

#define CR_PREFETCH_DIST        3

#if !defined(P2_CR_NO_PREFETCH) && (!defined(P2_CR_VARC) || defined(P2_CR_VARC_PREFETCH))
static inline void cr_prefetch_t0(const void *p) {
    __asm__ volatile ("prefetcht0 (%0)" :: "r"(p));
}
#endif

static inline uint8_t call_004A8300(uint32_t fn, uint8_t *self) {
    uint32_t ret, d_ecx, d_edx;
    __asm__ volatile (
        "call *%3"
        : "=a"(ret), "=c"(d_ecx), "=d"(d_edx)
        : "r"(fn), "a"(self)
        : "cc", "memory");
    return (uint8_t)(ret & 0xFFu);
}

static inline void *call_op_new(uint32_t fn, uint32_t size) {
    void *ret;
    uint32_t d_ecx, d_edx;
    __asm__ volatile (
        "pushl %4\n\t"
        "call *%3\n\t"
        "addl $4, %%esp"
        : "=a"(ret), "=c"(d_ecx), "=d"(d_edx)
        : "r"(fn), "r"(size)
        : "cc", "memory");
    return ret;
}

static inline void *call_005163C0(uint32_t fn, void *buf) {
    void *ret;
    uint32_t d_ecx, d_edx;
    __asm__ volatile (
        "call *%3"
        : "=a"(ret), "=c"(d_ecx), "=d"(d_edx)
        : "r"(fn), "a"(buf)
        : "cc", "memory");
    return ret;
}

static inline void call_vtable_28(uint8_t *cmd) {
    uint32_t fn = *(uint32_t *)(*(uint8_t **)cmd + 0x28);
    uint32_t d_eax, d_ecx, d_edx;
    __asm__ volatile (
        "call *%3"
        : "=a"(d_eax), "=c"(d_ecx), "=d"(d_edx)
        : "r"(fn), "c"(cmd)
        : "cc", "memory");
}

static inline void call_vtable_2c(uint8_t *cmd) {
    uint32_t fn = *(uint32_t *)(*(uint8_t **)cmd + 0x2C);
    uint32_t d_eax, d_ecx, d_edx;
    __asm__ volatile (
        "call *%3"
        : "=a"(d_eax), "=c"(d_ecx), "=d"(d_edx)
        : "r"(fn), "c"(cmd)
        : "cc", "memory");
}

static inline uint32_t call_vtable_1c(uint8_t *obj) {
    uint32_t fn = *(uint32_t *)(*(uint8_t **)obj + 0x1C);
    uint32_t ret, d_ecx, d_edx;
    __asm__ volatile (
        "call *%3"
        : "=a"(ret), "=c"(d_ecx), "=d"(d_edx)
        : "r"(fn), "c"(obj)
        : "cc", "memory");
    return ret;
}

static inline void call_vtable_00_del1(uint8_t *cmd) {
    uint32_t fn = *(uint32_t *)(*(uint8_t **)cmd + 0x00);
    uint32_t d_eax, d_ecx, d_edx;
    __asm__ volatile (
        "pushl $1\n\t"
        "call *%3"
        : "=a"(d_eax), "=c"(d_ecx), "=d"(d_edx)
        : "r"(fn), "c"(cmd)
        : "cc", "memory");
}

static inline void call_004A7BC0(uint32_t fn, uint8_t *list_ptr, void *ptr) {
    uint32_t d_eax, d_ecx, d_edx;
    __asm__ volatile (
        "pushl %4\n\t"
        "call *%3"
        : "=a"(d_eax), "=c"(d_ecx), "=d"(d_edx)
        : "r"(fn), "r"(ptr), "S"(list_ptr)
        : "cc", "memory");
}

static inline void call_005F2AE0(uint32_t fn, uint8_t *list_ptr, void *node) {
    uint32_t d_eax, d_ecx, d_edx;
    __asm__ volatile (
        "pushl %4\n\t"
        "call *%3"
        : "=a"(d_eax), "=c"(d_ecx), "=d"(d_edx)
        : "r"(fn), "r"(node), "S"(list_ptr)
        : "cc", "memory");
}

static inline void call_vec_push(uint32_t fn, void *item_ptr, void *vec_ptr) {
    uint32_t d_eax, d_ecx, d_edx;
    __asm__ volatile (
        "call *%3"
        : "=a"(d_eax), "=c"(d_ecx), "=d"(d_edx)
        : "r"(fn), "a"(item_ptr), "D"(vec_ptr)
        : "cc", "memory");
}

static inline uint8_t call_00511140(uint32_t fn, void *self_tag_ptr, void *other) {
    uint32_t ret, d_ecx, d_edx;
    __asm__ volatile (
        "pushl %4\n\t"
        "call *%3"
        : "=a"(ret), "=c"(d_ecx), "=d"(d_edx)
        : "r"(fn), "r"(other), "d"(self_tag_ptr)
        : "cc", "memory");
    return (uint8_t)(ret & 0xFFu);
}

static inline uint32_t call_009692C0(uint32_t fn, void *arg_a8) {
    uint32_t ret, d_ecx, d_edx;
    __asm__ volatile (
        "call *%3"
        : "=a"(ret), "=c"(d_ecx), "=d"(d_edx)
        : "r"(fn), "a"(arg_a8)
        : "cc", "memory");
    return ret;
}

static inline int32_t call_round_ftol2(uint32_t f_bits, uint32_t fn_round, uint32_t fn_ftol2) {
    int32_t res;
    uint32_t d_ecx, d_edx;
    __asm__ volatile (
        "pushl %3\n\t"
        "call *%4\n\t"
        "addl $4, %%esp\n\t"
        "call *%5"
        : "=a"(res), "=c"(d_ecx), "=d"(d_edx)
        : "r"(f_bits), "r"(fn_round), "S"(fn_ftol2)
        : "cc", "memory");
    return res;
}

typedef struct CRTagPair {
    uint32_t tag;
    uint32_t id;
} CRTagPair;

static inline __attribute__((always_inline)) void cr_sese_process_tag(
    uint32_t base, uint8_t *self, uint32_t other_id, uint32_t other_tag
) {
    CRTagPair pair;
    pair.tag = other_tag;
    pair.id = other_id;

    uint8_t *relation = (*(uint8_t * const **)(self + 0xBE8))[other_id];

    /* 0x00515F49..0x00515FC6 */
    if (call_004A8300(base + RVA_FN_004A8300, self) != 0u &&
        *(const uint32_t *)(self + 0xCFC) == other_id &&
        *(volatile uint32_t *)(relation + 0x20) == 0u) {
        uint8_t *cmd = (uint8_t *)call_op_new(base + RVA_FN_OP_NEW, 0x24u);
        if (cmd) {
            cmd = (uint8_t *)call_005163C0(base + RVA_FN_005163C0, cmd);
        }
        uint8_t *w = *(uint8_t * const *)(base + RVA_GLOBAL_WORLD);
        uint32_t w_b0c = *(const uint32_t *)(w + 0xB0C);
        *(uint32_t *)(cmd + 0x0C) = *(const uint32_t *)(self + 0x20);
        *(uint32_t *)(cmd + 0x08) = *(const uint32_t *)(self + 0x1C);
        *(uint32_t *)(cmd + 0x10) = pair.tag;
        *(uint32_t *)(cmd + 0x14) = pair.id;
        *(uint32_t *)(cmd + 0x18) = w_b0c;
        call_vtable_28(cmd);
        uint8_t *w_after = *(uint8_t * const *)(base + RVA_GLOBAL_WORLD);
        call_004A7BC0(base + RVA_FN_004A7BC0, w_after + 0xA7C, cmd);
    }

    /* 0x00515FCB..0x00515FE6 (re-reads volatile relation+0x20) */
    if (*(volatile uint32_t *)(relation + 0x20) != 0u) {
        ++(*(uint32_t *)(self + 0xDD8));
        call_vec_push(base + RVA_FN_004D61D0, &pair, self + 0xD58);
    }

    /* 0x00515FEA..0x00516016 */
    uint8_t *rel28 = *(uint8_t * volatile *)(relation + 0x28);
    if (rel28 != NULL) {
        if (*(const uint32_t *)(rel28 + 0x0C) == *(const uint32_t *)(relation + 0x0C)) {
            call_vec_push(base + RVA_FN_004D61D0, &pair, self + 0xD78);
        }
    }

    /* 0x0051601A..0x0051606E */
    uint8_t *rel24 = *(uint8_t * volatile *)(relation + 0x24);
    if (rel24 != NULL) {
        uint32_t kind = call_vtable_1c(rel24);
        if (kind == 0x336u || call_vtable_1c(rel24) == 0x93Au) {
            uint8_t *rel24_now = *(uint8_t * const *)(relation + 0x24);
            if (*(const uint32_t *)(rel24_now + 0x14) == *(const uint32_t *)(relation + 0x0C)) {
                ++(*(uint32_t *)(self + 0xDDC));
                call_vec_push(base + RVA_FN_004D61D0, &pair, self + 0xD38);
            }
        }
    }

    /* 0x00516072..0x005160B5 */
    uint8_t *rel24_b = *(uint8_t * volatile *)(relation + 0x24);
    if (rel24_b != NULL && call_vtable_1c(rel24_b) == 0x93Au) {
        uint8_t *rel24_now = *(uint8_t * const *)(relation + 0x24);
        if (*(const uint32_t *)(rel24_now + 0x14) == *(const uint32_t *)(relation + 0x0C)) {
            ++(*(uint32_t *)(self + 0xDE0));
            call_vec_push(base + RVA_FN_004D61D0, &pair, self + 0xD48);
        }
    }

    /* 0x005160B9..0x00516133 */
    int push_d68 = 0;
    if (*(volatile uint32_t *)(relation + 0x20) != 0u ||
        *(volatile uint32_t *)(relation + 0x24) != 0u ||
        *(const uint32_t *)(self + 0x142C) == other_id) {
        push_d68 = 1;
    } else {
        uint32_t *mgr_now = *(uint32_t * const *)(base + RVA_GLOBAL_COUNTRY_MGR);
        uint8_t *other_cf = (*(uint8_t * const **)(mgr_now + 1))[other_id];
        if (*(const uint8_t *)(other_cf + 0xCF4) != 0u &&
            *(const uint8_t *)(self + 0xCF4) != 0u &&
            *(const uint32_t *)(other_cf + 0xCFC) == *(const uint32_t *)(self + 0xCFC)) {
            push_d68 = 1;
        } else if (*(volatile uint8_t *)(relation + 0x70) != 0u) {
            push_d68 = 1;
        }
    }
    if (push_d68) {
        call_vec_push(base + RVA_FN_004D61D0, &pair, self + 0xD68);
    }

    /* 0x00516134..0x005161C2 */
    uint8_t *cmd38 = *(uint8_t * volatile *)(relation + 0x38);
    if (cmd38 != NULL) {
        uint32_t *mgr_now = *(uint32_t * const *)(base + RVA_GLOBAL_COUNTRY_MGR);
        uint8_t *other_cur = (*(uint8_t * const **)(mgr_now + 1))[other_id];
        if (*(const uint8_t *)(other_cur + 0x67C) != 0u &&
            *(volatile uint32_t *)(relation + 0x34) == 0u) {
            uint8_t *pushed_other = other_cur;
            call_vec_push(base + RVA_FN_004E9B90, &pushed_other, self + 0xEA4);
        } else {
            uint8_t *w = *(uint8_t * const *)(base + RVA_GLOBAL_WORLD);
            uint8_t *node = *(uint8_t * const *)(w + 0xA84);
            while (node != NULL && *(uint8_t * const *)node != cmd38) {
                node = *(uint8_t * const *)(node + 8);
            }
            call_005F2AE0(base + RVA_FN_005F2AE0, w + 0xA84, node);
            call_vtable_2c(cmd38);
            *(volatile uint8_t *)(relation + 0x71) = 1u;
            *(volatile uint32_t *)(relation + 0x38) = 0u;
            call_vtable_00_del1(cmd38);
        }
    }

    /* 0x005161C4..0x005161FE */
    uint32_t *mgr_s7 = *(uint32_t * const *)(base + RVA_GLOBAL_COUNTRY_MGR);
    uint8_t *other_s7 = (*(uint8_t * const **)(mgr_s7 + 1))[other_id];
    if (call_00511140(base + RVA_FN_00511140, self + 0x1C, other_s7) != 0u) {
        uint32_t *mgr_s7_b = *(uint32_t * const *)(base + RVA_GLOBAL_COUNTRY_MGR);
        uint8_t *pushed_other2 = (*(uint8_t * const **)(mgr_s7_b + 1))[other_id];
        call_vec_push(base + RVA_FN_004E9B90, &pushed_other2, self + 0xEB4);
    }

    /* 0x005161FF..0x00516272 */
    uint8_t *lnode = *(uint8_t * const *)(self + 0x9F8);
    while (lnode != NULL) {
        uint32_t elem_idx = *(const uint32_t *)lnode;
        uint8_t *w_acc = *(uint8_t * const *)(base + RVA_GLOBAL_WORLD);
        uint8_t * const *acc = *(uint8_t * const **)(w_acc + 0xACC);
        uint8_t *elem = acc[elem_idx];
        lnode = *(uint8_t * const *)(lnode + 8);
        if (*(const uint32_t *)(elem + 0x12C) == other_id) {
            uint32_t self_e64 = *(const uint32_t *)(self + 0xE64);
            uint32_t dom = call_009692C0(base + RVA_FN_009692C0, elem + 0x1A8);
            if (dom == self_e64) {
                *(int32_t *)(self + 0x1AC) += 0x3E8;
            } else {
                uint32_t f_bits = *(const uint32_t *)(base + RVA_CONST_250_5F);
                int32_t delta = call_round_ftol2(
                    f_bits,
                    base + RVA_FN_ROUND,
                    base + RVA_FN_FTOL2_SSE
                );
                *(int32_t *)(self + 0x1AC) += delta;
            }
        }
    }
}

#ifdef P2_CR_VARC
static inline uint32_t cr_bsf32(uint32_t x) {
    uint32_t r;
    __asm__ ("bsf %1, %0" : "=r"(r) : "r"(x));
    return r;
}

static inline uint32_t cr_is_tag_alive(uint8_t * const *entries, uint32_t total_tags, uint32_t idx) {
    uint8_t *entry = entries[idx];
    if (!entry) {
        return 0u;
    }
    uint32_t other_id = *(const uint32_t *)(entry + 0x20u);
    uint32_t other_tag = *(const uint32_t *)(entry + 0x1Cu);
    if (other_id == 0u || (other_tag & 0x00FFFFFFu) == 0x00424552u || other_id >= total_tags) {
        return 0u;
    }
    uint8_t *other = entries[other_id];
    if (!other) {
        return 0u;
    }
    int32_t prov_diff = *(const int32_t *)(other + 0x9DCu) - *(const int32_t *)(other + 0x9D8u);
    return ((prov_diff & ~3) > 0) ? 1u : 0u;
}
#endif

static inline void cr_sese_full_scan(
    uint32_t base, uint8_t *self, uint32_t self_id, uint32_t *country_mgr, int32_t total_tags
) {
#if !defined(P2_CR_NO_PREFETCH) && !defined(P2_CR_VARC)
    uint8_t * const *self_relations = *(uint8_t * const **)(self + 0xBE8);
#endif
    for (int32_t idx = 0; idx < total_tags; ++idx) {
        uint8_t * const *loop_entries = *(uint8_t * const **)(country_mgr + 1);

#if !defined(P2_CR_NO_PREFETCH) && !defined(P2_CR_VARC)
        if (idx + CR_PREFETCH_DIST < total_tags) {
            uint8_t *p_entry = loop_entries[idx + CR_PREFETCH_DIST];
            if (p_entry) {
                cr_prefetch_t0(p_entry);
                uint32_t p_id = *(const uint32_t *)(p_entry + 0x20);
                if (p_id < (uint32_t)total_tags) {
                    uint8_t *p_other = loop_entries[p_id];
                    if (p_other) {
                        cr_prefetch_t0(p_other + 0x9D8);
                    }
                    if (self_relations) {
                        cr_prefetch_t0(&self_relations[p_id]);
                        uint8_t *p_rel = self_relations[p_id];
                        if (p_rel) {
                            cr_prefetch_t0(p_rel + 0x70);
                        }
                    }
                }
            }
        }
#endif

        uint8_t *entry = loop_entries[idx];
        uint32_t other_id = *(const uint32_t *)(entry + 0x20);
        uint32_t other_tag = *(const uint32_t *)(entry + 0x1C);

        if (other_id == self_id || other_id == 0u) {
            continue;
        }
        /* Reject "REB" (bytes 'R'=0x52, 'E'=0x45, 'B'=0x42) */
        if ((other_tag & 0x00FFFFFFu) == 0x00424552u) {
            continue;
        }

        uint32_t *mgr_g = *(uint32_t * const *)(base + RVA_GLOBAL_COUNTRY_MGR);
        uint8_t *other = (*(uint8_t * const **)(mgr_g + 1))[other_id];
        int32_t prov_diff = *(const int32_t *)(other + 0x9DC) - *(const int32_t *)(other + 0x9D8);
        if ((prov_diff & ~3) <= 0) {
            continue;
        }

        cr_sese_process_tag(base, self, other_id, other_tag);
    }
}

void __cdecl cr_sese_body(uint8_t *self, uint8_t *esp_in, const P2CrConfig *cfg) {
    uint32_t base = cfg->exe_base;
    uint32_t *country_mgr = *(uint32_t **)(esp_in + 0x28);
    int32_t total_tags = *(volatile int32_t *)country_mgr;

    /* Required post-loop contract at 0x005162CF / 0x0051630F */
    *(int32_t *)(esp_in + 0x18) = total_tags;
    if (total_tags <= 0) {
        return;
    }

    uint32_t self_id = *(const uint32_t *)(self + 0x20);

#ifdef P2_CR_VARC
    CRVarCState *st = (CRVarCState *)(uintptr_t)cfg->varc_state;
    if (!st || (uint32_t)total_tags > P2_VARC_MAX_TAGS) {
        cr_sese_full_scan(base, self, self_id, country_mgr, total_tags);
        return;
    }

    uint8_t * const *entries = *(uint8_t * const **)(country_mgr + 1);
    uint32_t n_words = ((uint32_t)total_tags + 31u) >> 5;
    if (st->initialized == 0u || st->dirty != 0u ||
        st->total_tags != (uint32_t)total_tags ||
        st->entries_ptr != (uint32_t)(uintptr_t)entries) {
        for (uint32_t w = 0u; w < n_words; ++w) {
            st->alive_bits[w] = 0u;
        }
        for (uint32_t i = 0u; i < (uint32_t)total_tags; ++i) {
            if (cr_is_tag_alive(entries, (uint32_t)total_tags, i)) {
                st->alive_bits[i >> 5] |= (1u << (i & 31u));
            }
        }
        st->total_tags = (uint32_t)total_tags;
        st->entries_ptr = (uint32_t)(uintptr_t)entries;
        st->dirty = 0u;
        st->initialized = 1u;
    } else if (cfg->varc_mode == P2_VARC_VALIDATE) {
        for (uint32_t i = 0u; i < (uint32_t)total_tags; ++i) {
            uint32_t exp_bit = cr_is_tag_alive(entries, (uint32_t)total_tags, i);
            uint32_t act_bit = (st->alive_bits[i >> 5] >> (i & 31u)) & 1u;
            if (exp_bit != act_bit) {
                st->mismatch_count += 1u;
                st->last_mismatch_idx = i;
                st->last_expected = exp_bit;
                st->last_actual = act_bit;
                if (exp_bit) {
                    st->alive_bits[i >> 5] |= (1u << (i & 31u));
                } else {
                    st->alive_bits[i >> 5] &= ~(1u << (i & 31u));
                }
                if (st->mismatch_cb != 0u) {
                    typedef void (__cdecl *MismatchCb)(uint32_t, uint32_t, uint32_t, uint32_t);
                    MismatchCb cb = (MismatchCb)(uintptr_t)st->mismatch_cb;
                    cb(i, exp_bit, act_bit, st->mismatch_count);
                }
            }
        }
    }

#ifdef P2_CR_VARC_PREFETCH
    uint8_t * const *self_relations = *(uint8_t * const **)(self + 0xBE8);
#endif
    for (uint32_t w = 0u; w < n_words; ++w) {
        uint32_t mask = st->alive_bits[w];
        if (w + 1u == n_words) {
            uint32_t rem = (uint32_t)total_tags & 31u;
            if (rem != 0u) {
                mask &= (1u << rem) - 1u;
            }
        }
        while (mask != 0u) {
            uint32_t bit = cr_bsf32(mask);
            mask &= (mask - 1u);
            uint32_t idx = (w << 5) | bit;
#ifdef P2_CR_VARC_PREFETCH
            if (mask != 0u) {
                uint32_t nbit = cr_bsf32(mask);
                uint32_t nidx = (w << 5) | nbit;
                uint8_t * const *cur_entries = *(uint8_t * const **)(country_mgr + 1);
                uint8_t *nentry = cur_entries[nidx];
                if (nentry) {
                    cr_prefetch_t0(nentry);
                    uint32_t nid = *(const uint32_t *)(nentry + 0x20u);
                    if (nid < (uint32_t)total_tags && self_relations) {
                        cr_prefetch_t0(&self_relations[nid]);
                        uint8_t *nrel = self_relations[nid];
                        if (nrel) {
                            cr_prefetch_t0(nrel + 0x70u);
                        }
                    }
                }
            }
#endif
            uint8_t * const *loop_entries = *(uint8_t * const **)(country_mgr + 1);
            uint8_t *entry = loop_entries[idx];
            uint32_t other_id = *(const uint32_t *)(entry + 0x20u);
            uint32_t other_tag = *(const uint32_t *)(entry + 0x1Cu);
            if (other_id == self_id || other_id == 0u) {
                continue;
            }
            cr_sese_process_tag(base, self, other_id, other_tag);
        }
    }
#else
    cr_sese_full_scan(base, self, self_id, country_mgr, total_tags);
#endif
}
