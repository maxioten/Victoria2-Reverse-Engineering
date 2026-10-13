# POP and factory payloads versus list nodes

For the English Windows Victoria II: Heart of Darkness 3.04 executable,
object payloads and their owning list nodes have different extents. A node
contains the payload at its **unchanged allocation base**, followed by list
links and a byte marker. There is no prefix/header to skip.

All addresses below are preferred **VAs**, with image base `0x00400000`, not
RVAs. Extents and instruction chains are static evidence; selected factory
field meanings also have narrow runtime/save correlations.

## Storage boundaries

| Object | Payload / contiguous value-copy stride | Linked-node allocation | Previous | Next | Marker |
| --- | --- | --- | --- | --- | --- |
| `CPop` | `0x278` | `0x288` | `+0x278` | `+0x27C` | `+0x280` (byte) |
| Factory (`CStateBuilding`) | `0x220` | `0x230` | `+0x220` | `+0x224` | `+0x228` (byte) |

Offsets are from the complete object/node base. Live nodes are **separately
allocated and linked**, not a contiguous node array. Follow the next pointer;
neither node allocation size is an array traversal stride. A reader of links
must cover storage beyond the payload. Marker lifecycle and trailing node
bytes remain uncharacterized.

## Native extent proof

- **POP values:** copy helper VA `0x004C0AF0` calls copy constructor
  `0x00955450`, then advances source/destination by `0x278` at
  `0x004C0B38/0x004C0B45`. Constructors initialize/copy through dword `+0x274`.
- **POP nodes:** VAs `0x004B8D8E/0x004BE161` request `0x288` allocations.
  The returned base reaches `0x00955450` unchanged at
  `0x004B8DBA/0x004BE183`; subsequent writes initialize previous/next/byte
  marker at `+0x278/+0x27C/+0x280`.
- **Factory values:** helper VA `0x004C0A50` calls copy constructor
  `0x004F2E50`, then advances destination/source by `0x220` at
  `0x004C0A97/0x004C0AA4`.
- **Factory nodes:** VA `0x004CF426` requests `0x230`; allocator call
  `0x004CF42F` returns the base passed unchanged to `0x004F2E50` at
  `0x004CF44A`. VAs `0x004CF453/0x004CF459/0x004CF463` initialize
  previous/next/byte marker at `+0x220/+0x224/+0x228`.

These paths distinguish value-copy strides from owning-node allocations.
They do not prove that every byte is initialized or every runtime pointer is
live/readable. The historical `0x2A8` POP extent is unsupported for these
objects; the separate [patch reconciliation](../Patch/PATCHES.md) in section 7.7
does not establish whether the patch's traversal is correct.

## Factory injection and project fields

| Complete-object offset | Meaning | Evidence |
| --- | --- | --- |
| `+0x1D0` | `CGoodsProject*`, not money | Load allocates `0xC0`, calls RTTI-identified constructor VA `0x00860390`, and stores the pointer. Close VA `0x004F5750` deletes the pointed-to object and nulls the slot. |
| `+0x1D8/+0x1DC` | Int64 subsidy amount, not days | Finance VA `0x004F4B30` writes both halves at `0x004F4D0A/0x004F4D10`. |
| `+0x210/+0x214` | Int64 `injected_money` remaining, /32768 | Named serialization token `0x6C4`; writer reads at `0x004F4346/0x004F434C`. |
| `+0x218` | Int32 `injected_days` remaining | Named token `0x6C5`; writer reads at `0x004F4394`. |

Writer VA `0x004F3EF0` receives the serialization subobject at complete-object
`+8`. Its relative `+0x208/+0x20C` money and `+0x210` days therefore mean
complete-object `+0x210/+0x214` and `+0x218`, respectively.

Tranche function VA `0x004F56B0` divides remaining money by remaining days,
subtracts the tranche from `+0x210`, decrements `+0x218`, adds the tranche to
budget `+0x150` and records investment at `+0x170`. On the final day it consumes
the whole remainder. These are deferred-funding countdown fields, not a
constant daily amount. This mechanism does not establish general funding
policy, full project/marker lifecycle, or safe direct mutation.
