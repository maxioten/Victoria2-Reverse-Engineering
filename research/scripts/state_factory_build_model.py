#!/usr/bin/env python3
"""
Python reference model for CState::CanBuildFactory (0x004D04B0..0x004D0692).
Simulates state factory eligibility, colonial restriction, 8-factory cap,
duplicate type prevention, AI category reservation, and technology prerequisites.
"""

def check_state_can_build_factory(
    is_colonial: int,
    factory_count: int,
    existing_factory_types: list[int],
    candidate_type: int,
    is_ai: bool,
    existing_flags_13a: list[int] = None,
    existing_flags_13b: list[int] = None,
    candidate_flag_13a: int = 0,
    candidate_flag_13b: int = 0,
    candidate_requires_coastal: int = 0,
    state_has_coastal_province: bool = True,
    tech_prereq_present: bool = False,
    country_has_tech: bool = True,
    tech_requires_port: bool = False,
    state_has_port: bool = True
) -> int:
    """
    Simulates CState::CanBuildFactory.
    Returns 1 if buildable, 0 otherwise.
    """
    # 0x004D04BC: cmp dword ptr [ecx + 0x84], 0; jle 0x4d04d3; xor al, al; ret
    if is_colonial > 0:
        return 0

    # 0x004D04D3: mov eax, 8; sub eax, dword ptr [ecx + 0x68]; cmp eax, 1; jl 0x4d04c8
    rem_slots = 8 - factory_count
    if rem_slots < 1:
        return 0

    # AI heuristics block (0x004D04E4..0x004D062F)
    if is_ai:
        has_13a = any(x != 0 for x in (existing_flags_13a or []))
        has_13b = any(x != 0 for x in (existing_flags_13b or []))

        # 0x004D053D: if candidate has 13b and state has 13b -> return 0
        if candidate_flag_13b != 0 and has_13b:
            return 0
        # 0x004D054B: if candidate has 13a and state has 13a -> return 0
        if candidate_flag_13a != 0 and has_13a:
            return 0

        # 0x004D0557: if candidate type is not already built and rem_slots <= 2
        if candidate_type not in existing_factory_types:
            if rem_slots <= 2:
                # 0x004D0562: test al, al (candidate 13a); jne 0x4d056e; test dl, dl (has 13a); je 0x4d04c8
                if candidate_flag_13a == 0 and not has_13a:
                    return 0
                # 0x004D056E: test cl, cl (candidate 13b); jne 0x4d057a; test bl, bl (has 13b); je 0x4d04c8
                if candidate_flag_13b == 0 and not has_13b:
                    return 0

        # 0x004D057A: if candidate requires coastal (+0xD8 != 0)
        if candidate_requires_coastal != 0 and not state_has_coastal_province:
            return 0

    # Duplicate factory type in state (0x004D0640..0x004D0649)
    if candidate_type in existing_factory_types:
        return 0

    # Tech prerequisite (0x004D0653..0x004D0684)
    if tech_prereq_present:
        if not country_has_tech:
            return 0
        if tech_requires_port and not state_has_port:
            return 0

    # 0x004D068C: mov al, 1; ret
    return 1
