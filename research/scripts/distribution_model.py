"""Operational reconstruction of VA 004BE780; bit patterns and x86 guard flags explicit."""
from integer_model import MASK, signed, trunc_div

def normalize_distribution(values):
    original = [value & MASK for value in values]
    result = original.copy()
    if len(original) <= 1:
        return result, {'normalized':False,'reason':'no_data_slots'}
    data_count = len(original) - 1
    pairs = data_count // 2
    group_a = sum(original[1 + 2*i] for i in range(pairs)) & MASK
    group_b = sum(original[2 + 2*i] for i in range(pairs)) & MASK
    combined = (group_a + group_b) & MASK
    tail = original[-1] if data_count % 2 else 0
    low_total = (tail & 0xffffffff) + (combined & 0xffffffff)
    high_a, high_b = tail >> 32, combined >> 32
    high_total = (high_a + high_b + (low_total >> 32)) & 0xffffffff
    total = (high_total << 32) | (low_total & 0xffffffff)
    overflow = bool((~(high_a ^ high_b) & (high_a ^ high_total)) & 0x80000000)
    negative = bool(high_total & 0x80000000)
    # Actual JS/JG/unsigned-low comparison sequence, including the ADC overflow flag.
    normalize = not negative and ((high_total != 0 and not overflow) or (low_total & 0xffffffff) != 0)
    info = {'normalized':normalize,'sum_bits':hex(total),'final_adc_overflow':overflow,
            'naive_positive_sum_guard':signed(total)>0}
    if not normalize:
        return result, info
    divisor = signed(total)
    assert divisor > 0
    for i in range(1,len(original)):
        product_bits = (original[i] * 0x320000) & MASK
        result[i] = trunc_div(signed(product_bits),divisor) & MASK
    return result, info
