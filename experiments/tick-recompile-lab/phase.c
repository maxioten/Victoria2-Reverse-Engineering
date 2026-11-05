/* Reconstructed 1000-draw tick phase, not original source.
 * Target SHA256 62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648
 * Original block RVA 0x285b69..0x285c09, preferred base 0x00400000.
 * Preconditions: existing singleton, accessible disjoint state/counter/output,
 * index 0..623, no concurrent RNG access. Does not implement singleton allocation.
 */
#include <stdint.h>

static uint32_t sar32(uint32_t value, unsigned shift) {
    return (value >> shift) | ((0u - (value >> 31)) << (32 - shift));
}

static void regenerate(uint32_t *state) {
    for (unsigned i = 0; i < 624; ++i) {
        uint32_t mixed = (state[i] & 0x80000000u) |
                         (state[(i + 1) % 624] & 0x7fffffffu);
        /* Signed remainder == +1 excludes negative odd mixed values. */
        uint32_t twist = ((mixed & 0x80000001u) == 1u) ? 0x9908b0dfu : 0u;
        state[i] = state[(i + 397) % 624] ^ sar32(mixed, 1) ^ twist;
    }
}

uint32_t phase_c(uint32_t *state, uint32_t *counter, uint32_t *output) {
    uint32_t last = 0;
    for (unsigned i = 0; i < 1000; ++i) {
        ++*counter;
        uint32_t index = state[624];
        if (index == 0) regenerate(state);
        uint32_t value = state[index];
        value ^= sar32(value, 11);
        value ^= (value & 0xff3a58adu) << 7;
        value ^= (value & 0xffffdf8cu) << 15;
        value ^= sar32(value, 18);
        #ifdef V2_BAD_OUTPUT
        value ^= 1u; /* Deliberately incorrect candidate for the negative control. */
#endif
        output[i] = last = value;
        state[624] = (index + 1) % 624;
    }
    return last;
}
