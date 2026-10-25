#!/usr/bin/env python3
"""
Python reference model for CBuildingProject::UpdateFundingStatus (0x004A4EB0..0x004A4F2E).
Computes project funding requirement boolean based on stage, current funds, and 110% buffer.
"""

def compute_project_funding_status(stage: int, current_funds: int, base_cost: int) -> tuple[int, int]:
    """
    Simulates CBuildingProject::UpdateFundingStatus.
    
    Args:
        stage: 32-bit integer project stage (offset +0x7C).
        current_funds: 64-bit integer invested funds (offsets +0x60 and +0x64).
        base_cost: 64-bit integer base cost returned by 0x004A5020.
        
    Returns:
        (needs_funding, eax_return): both represent the status (1 = needs funds, 0 = satisfied/closed).
    """
    stage_32 = stage & 0xFFFFFFFF
    if stage_32 >= 0x80000000:
        stage_s = stage_32 - 0x100000000
    else:
        stage_s = stage_32

    # Check stage condition
    # 0x004A4EBA: test eax, eax; js 0x4A4F1E
    # 0x004A4EBE: cmp eax, 1; jle 0x4A4EC8
    # 0x004A4EC3: cmp eax, 3; jne 0x4A4F1E
    if stage_s < 0 or stage_s == 2 or stage_s >= 4:
        # 0x004A4F1E: cmp eax, 4; setne al; mov [esi+0x80], al; ret
        status = 0 if stage_s == 4 else 1
        # setne al only modifies the lowest byte of eax, preserving bits 8..31 of stage
        eax = (stage_32 & ~0xFF) | status
        return status, eax

    # Active funding stages: 0, 1, 3
    # 0x004A4ED3: fld double [0x00E45BA0] (36045.30078125)
    # 0x004A4EDB: call _ftol2 -> 36045
    mult = 36045
    prod = (base_cost * mult) & 0xFFFFFFFFFFFFFFFF
    if prod >= 0x8000000000000000:
        prod_s = prod - 0x10000000000000000
    else:
        prod_s = prod

    # 0x004A4EEE: shrd eax, edx, 0xf
    # 0x004A4EF2: sar edx, 0xf
    thresh_s = prod_s >> 15
    thresh = thresh_s & 0xFFFFFFFFFFFFFFFF

    curr_u64 = current_funds & 0xFFFFFFFFFFFFFFFF
    curr_high = (curr_u64 >> 32) & 0xFFFFFFFF
    if curr_high >= 0x80000000:
        curr_high -= 0x100000000
    thr_high = (thresh >> 32) & 0xFFFFFFFF
    if thr_high >= 0x80000000:
        thr_high -= 0x100000000

    # 0x004A4EF5: cmp dword ptr [esi + 0x64], edx
    # 0x004A4EF8: jg 0x4A4F11  (status = 0)
    # 0x004A4EFA: jl 0x4A4F01  (status = 1)
    if curr_high > thr_high:
        return 0, 0
    elif curr_high < thr_high:
        return 1, 1
    else:
        # 0x004A4EFC: cmp dword ptr [esi + 0x60], eax
        # 0x004A4EFF: jae 0x4A4F11 (status = 0)
        curr_low = curr_u64 & 0xFFFFFFFF
        thr_low = thresh & 0xFFFFFFFF
        if curr_low >= thr_low:
            return 0, 0
        else:
            return 1, 1
