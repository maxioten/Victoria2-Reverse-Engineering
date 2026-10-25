"""Explicit 64-bit bit-pattern model and deterministic fixtures; not original source."""
import random

MASK = (1 << 64) - 1

def signed(bits):
    return bits if bits < (1 << 63) else bits - (1 << 64)

def trunc_div(a, b):
    quotient = abs(a) // abs(b)
    return -quotient if (a < 0) != (b < 0) else quotient

def test_pairs():
    edges = [-(1<<63), -(1<<63)+1, -(1<<32)-1, -(1<<32), -(1<<31), -32768, -3, -2, -1,
             0, 1, 2, 3, 32767, 32768, (1<<31)-1, 1<<31, (1<<32)-1, 1<<32, (1<<63)-1]
    generator = random.Random(20261021)
    pairs = [(a,b) for a in edges for b in edges]
    pairs.extend((signed(generator.getrandbits(64)),signed(generator.getrandbits(64))) for _ in range(2048))
    pairs.extend((a,b) for a in ((1<<63)-1,(1<<63)-2,(1<<62)+12345)
                 for b in ((1<<32)+1,(1<<32)-1,(1<<33)+1,(1<<62)-1))
    pairs.extend((a,b) for a in ((1<<33)+1,-((1<<33)+1))
                 for b in ((1<<32)+1,-((1<<32)+1)))
    return pairs
