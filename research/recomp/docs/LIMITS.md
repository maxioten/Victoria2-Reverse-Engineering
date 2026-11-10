# Limits

## Lift is not decompilation

The 99,740 entries are a **static lift** of machine code to C, not source
reconstruction. A lifted function can compile and still differ from the
original source, types, names, side effects or calling convention.

Matching progress must be measured separately with `reccmp`, `objdiff` or
`rebrew`. At the time of this baseline, no function had been verified as a
byte-identical match.

## Coverage is not completeness

Byte coverage is 95.3 % of the declared code range. The remaining 4.7 %
(420,884 bytes) is not classified. It can be:

- data embedded in `.text`;
- alignment or padding;
- unreachable code;
- code the discovery pass did not separate into functions.

The number is a map of what the disassembler decoded, not proof that the
decoded set is complete.

## Function count is inflated by aliases

99,740 entries include 64,139 aliases. Only 35,601 are `start` entries. Any
progress metric should state whether it counts entries or unique bodies.

## `UNIMPLEMENTED` is a semantic gap

194 unique instruction sites in 13 definitions were not translated. The review
classifies 9 definitions as probable data and 4 as real code that only omits
`pause`. This is evidence, not proof that those bytes are data or that the
remaining functions are semantically complete.

## Differential tests are sampled

165 cases across 55 functions passed against Unicorn. That is a sample, not a
proof for every function or every input. The tests exclude:

- indirect calls;
- `fs:`/`gs:` and SEH;
- D3D9 and other device APIs;
- the top-of-stack return-address slots used by `RECOMP_CALL`.

## No executable was linked or run

The 101 C files compile to objects. No full executable was linked, no D3D9
device was created and the game was not booted. This baseline does not prove
playability or a performance improvement.

## Performance claims

The existing `Engine/performance-profile.md` measurements are the source for
the optimization plan. This directory does not add new performance
measurements. Any optimization must be benchmarked against the original on a
fixed save before it is claimed as an improvement.
