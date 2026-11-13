#include "p2_layout.h"

int __cdecl p2_dispatch(P2SavedState *regs, P2FxSave *fx, const P2HookConfig *cfg) {
    if (!cfg) {
        return P2_ACT_FALLBACK;
    }
    if (cfg->mode == P2_MODE_OFF) {
        return P2_ACT_FALLBACK;
    }
    if (cfg->mode == P2_MODE_SHADOW) {
        /* Refuse shadow-compare unless a shadow-capable comparator (flags bit 1) is registered. */
        if ((cfg->flags & 2u) == 0u || cfg->handler_fn == 0u) {
            return P2_ACT_FALLBACK;
        }
        P2HandlerFn fn = (P2HandlerFn)(uintptr_t)cfg->handler_fn;
        return fn(regs, fx, cfg);
    }
    if (cfg->mode != P2_MODE_PROD) {
        return P2_ACT_FALLBACK;
    }
    if (cfg->handler_fn != 0u) {
        P2HandlerFn fn = (P2HandlerFn)(uintptr_t)cfg->handler_fn;
        return fn(regs, fx, cfg);
    }
    if ((cfg->flags & 1u) != 0u) {
        return P2_ACT_HANDLED;
    }
    return P2_ACT_FALLBACK;
}
