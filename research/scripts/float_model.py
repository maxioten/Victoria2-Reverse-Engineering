"""Exact rational models of the declared masked conversion paths.

Models only result bits, not all x87 exception/status flags or arbitrary encodings.
"""
from fractions import Fraction
import math
import struct

def pow2(exponent):
    return Fraction(1 << exponent) if exponent >= 0 else Fraction(1, 1 << -exponent)

def floor_log2(value):
    assert value > 0
    exponent = value.numerator.bit_length() - value.denominator.bit_length()
    return exponent - (value < pow2(exponent))

def rounded_integer(value, mode):
    lower, remainder = divmod(value.numerator, value.denominator)
    if mode == 0:  # nearest, ties to even
        twice = remainder * 2
        return lower + (twice > value.denominator or (twice == value.denominator and lower & 1))
    if mode == 1: return lower  # down
    if mode == 2: return lower + (remainder != 0)  # up
    assert mode == 3
    return (abs(value.numerator) // value.denominator) * (-1 if value < 0 else 1)

def decode(format_id, bits):
    if format_id == 0:
        value = struct.unpack('>d', bytes.fromhex(bits))[0]
        return Fraction.from_float(value) if math.isfinite(value) else None
    assert format_id == 1
    raw = int(bits, 16)
    significand, high = raw & ((1 << 64)-1), raw >> 64
    exponent = high & 0x7fff
    if exponent == 0x7fff: return None
    assert (significand >> 63) == (exponent != 0), 'unsupported/pseudo extended encoding'
    value = significand * pow2((exponent if exponent else 1)-16383-63)
    return -value if high & 0x8000 else value

def encode_extended(value):
    value = Fraction(value)
    if value == 0: return '00000000000000000000'
    sign = 0x8000 if value < 0 else 0
    value = abs(value)
    exponent = floor_log2(value)
    significand = value / pow2(exponent-63)
    assert significand.denominator == 1 and (1 << 63) <= significand < (1 << 64)
    high = exponent + 16383
    assert 0 < high < 0x7fff
    return f'{((high | sign) << 64) | significand.numerator:020x}'

def quantize_binary64(value, mode):
    if value == 0: return value
    exponent = floor_log2(abs(value))
    assert exponent <= 63, 'current finite fixture range ends near signed64 boundaries'
    step = pow2(max(exponent, -1022)-52)
    return rounded_integer(value / step, mode) * step

def expected_bits(format_id, bits, fast, mode):
    value = decode(format_id, bits)
    width = 32 if fast else 64
    if value is None: return 1 << (width-1), False
    if fast:
        converted = quantize_binary64(value, mode)
        result = rounded_integer(converted, 3)
        valid = -(1 << 31) <= result < (1 << 31)
    else:
        intermediate = rounded_integer(value, mode)  # FISTP before correction
        valid = -(1 << 63) <= intermediate < (1 << 63)
        # The original low-zero/sign-only-high branch bypasses correction for
        # zero and INT64_MIN, even when the source was not that exact integer.
        result = intermediate if intermediate in (0, -(1 << 63)) else rounded_integer(value, 3)
    return (result if valid else 1 << (width-1)) & ((1 << width)-1), valid
