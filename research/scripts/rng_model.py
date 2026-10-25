"""Reconstructed operational model, not original source or standard MT19937.

Evidence and limits: docs/HALLAZGOS.md and scripts/verify_rng.py.
Words are unsigned 32-bit bit patterns; indices must be in [0, 623].
"""
MASK = 0xffffffff

def signed(word):
    return word if word < 0x80000000 else word - 0x100000000

def regenerate(words):
    for i in range(624):
        y = (words[i] & 0x80000000) | (words[(i + 1) % 624] & 0x7fffffff)
        value = words[(i + 397) % 624] ^ (signed(y) >> 1)
        # Signed remainder of a negative odd number is -1, not +1.
        if y < 0x80000000 and y & 1:
            value ^= 0x9908b0df
        words[i] = value & MASK

def temper(word, arithmetic=True):
    shift = (lambda x, n: signed(x) >> n) if arithmetic else (lambda x, n: x >> n)
    word = (word ^ shift(word, 11)) & MASK
    word = (word ^ ((word & 0xff3a58ad) << 7)) & MASK
    word = (word ^ ((word & 0xffffdf8c) << 15)) & MASK
    return (word ^ shift(word, 18)) & MASK

def initialize(seed):
    words = [seed]
    for i in range(1, 624):
        words.append(((words[-1] ^ (signed(words[-1]) >> 30)) * 0x6c078965 + i) & MASK)
    return words
