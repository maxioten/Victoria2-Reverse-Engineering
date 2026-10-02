# AI Ministers & Requests Registry — RTTI Enumeration (`CAI*` family)

> Grounded enumeration of all `CAI*` classes in `v2game.exe` v3.04 via MSVC RTTI
> (`type_descriptor` → Complete Object Locator → `vtable[-1]`), verified 2026-10-01.
> Method: `reverify strings` for `.?AVCAI*@@` names, then pointer-walk
> descriptor→COL→vtable with `tools/vic2_addr.py` + `tools/vic2_vtable.py`.
> All VAs below are Ghidra-style; file offsets verified with `reverify verify` (ledger).

## 1. Minister / Plan vtables (`CAIPlan` family layout)

All share slots 1–9 (`serialize 0x9A29F0/0x9C1A30`, tick `0x9C1390`,
init `0x825CF0`, CanExecute `0x825D40`, Update `0x826480`) and slot 11 relay `0xA46A60`.
Slot 5 = `0x4010C0` stub in every table.

| Class | Vtable VA | Vtable file | Slot 0 (dtor) | Slot 10 (Execute) | Execute file |
|---|---|---|---|---|---|
| `CAIAgent` (base) | `0xE26184` | `0xA24784` | `0x860DB0` | — (base) | — |
| `CAIArmy` | `0xE26374` | `0xA24974` | `0x827CA0` | `0x828030` | `0x427430` |
| `CAIBudgetMinister` | `0xE2657C` | `0xA24B7C` | `0x82E940` | `0x82E970` | `0x42DD70` |
| `CAIForeignMinister` | `0xE274FC` | `0xA25AFC` | `0x8336C0` | `0x833930` | `0x432D30` |
| `CAIKing` | `0xE27714` | `0xA25D14` | `0x84A350` | `0x84B0F0` | `0x44A4F0` |
| `CAIAdmiral` | `0xE27924` | `0xA25F24` | `0x84A080` | `0x821DC0` | `0x4211C0` |
| `CAINationalFocus` | `0xE27CCC` | `0xA262CC` | `0x853EF0` | `0x853FC0` | `0x4533C0` |
| `CAIMilitaryPlan` | `0xE27EB4` | `0xA264B4` | `0x855520` | `0x8555F0`?? see note | — |
| `CAINavalBlockadePlan` | `0xE280C4` | `0xA266C4` | `0x8555F0` | — | — |
| `CAIPoliticsMinister` | `0xE282D4` | `0xA268D4` | `0x855950` | `0x855980` | `0x454D80` |
| `CAIProductionMinister` | `0xE284DC` | `0xA26ADC` | `0x856930` | `0x8569A0` | `0x455DA0` |
| `CAIResearch` | `0xE286C4` | `0xA26CC4` | `0x859560` | `0x859610` | `0x458A10` |
| `CAIPlan` (base) | `0xE290FC` | `0xA276FC` | `0x860DB0` | `0x4010C0` (stub) | `0x4C0` |

Verified slot-10 words (file): `0xA26B04`=`A0 69 85 00` (Production),
`0xA268FC`=`80 59 85 00` (Politics), `0xA26CEC`=`10 96 85 00` (Research),
`0xA262F4`=`C0 3F 85 00` (NatFocus); slot-0 Production `0xA26ADC`=`30 69 85 00`.

> Note: `CAIMilitaryPlan` slot 10 reads the same value as `CAINavalBlockadePlan`
> slot 0 (`0x8555F0`) — the two tables are adjacent derivations; treat the
> MilitaryPlan-Execute assignment as provisional until its body is disassembled.

## 2. `CAIProductionMinister::Execute` (`0x8569A0`) — full body (`0x8569A0–0x857193`)

Verified structure (32/32 byte claims; ledger goal "CAIProductionMinister Execute body + helpers"):

- **Day gate** (`0x8569CF–0x856AC2`): `call 0x9B7610` (file `0x455DCF`), skip-all (`je 0x857182`) when `[ebx+0x68]` unchanged.
- **Slot/flag refresh**: flag bytes `[ebx+0x6C–0x74]`, cached-slot scans `[ebx+0x78/0x7C/0x80]`.
- **Threshold block** (`0x856E0F–0x856F54`): five DWORDs via `[0x12586DC]+0x60` chain, scaled by 64-bit helpers `0xAC9F20` (mul, file `0x6C9320`) / `0xAC02A0` (div, file `0x6BF6A0`) with constants 1000/3000/1000000.
- **Six gated phase calls** (each followed by `mov esi,[0x12587E4]` reload):
  - `0x858560` (file `0x457960`) / `0x858460` (file `0x457860`): paired slot-phases (slot fields `+0x7C`/`+0x80`), setups `0x857E60`/`0x8577B0`, shared tail `0x4DA790` — High (pairing) / Medium (role).
  - `0x858670` (file `0x457A70`): via enumerator pair `0x857430`+`0x857530`, tests `[ebx+0x6E]` — Medium-High.
  - `0x8582D0` (file `0x4576D0`): per-unit validation on slot `+0x78` via `0x8580E0` — Medium.
  - `0x8589B0` (file `0x457DB0`): batched variant sharing the `0x857430`+`0x857530` pair — Medium.
  - `0x859180` (file `0x458580`): per-item type-switched loop (`[eax+0xE44]` list, `[esi+0x244]` dispatch) — Medium.
- **Factory-scan loop + placement tail** (`0x8570FF–0x857180`): calls local `0x8571A0` (file `0x4565A0`), `0x57CC60` (record ctor, file `0x17C060`), two virtual calls.
- **Helpers**: `0x9B7610` RNG next-word (file `0x5B6A10`, xorshift masks; High), `0x9B7700` RNG refill (file `0x5B6B00`; High), `0x4DAD40` lazy container accessor (file `0xDA140`; High), `0x4DADA0` fixed-capacity (0x1FF) vector init (file `0xDA1A0`; High), `0x4DADF0` element release (file `0xDA1F0`; Medium), `0xAAD56B` allocator trampoline (file `0x6AC96B`; High), `0xAB6E30` fill/memset (file `0x6B6230`; High), `0xAAE9AF` allocator (file `0x6ADDAF`; Medium), `0xAAE91B` free trampoline (file `0x6ADD1B`; Medium).

## 3. `CAIPoliticsMinister::Execute` (`0x855980`), `CAIResearch::Execute` (`0x859610`), `CAINationalFocus::Execute` (`0x853FC0`) — heads

All three verified heads (files `0x454D80` / `0x458A10` / `0x4533C0`: `55 8B EC…`):

- **Politics** (`0x855980`): thiscall (`ebx = ecx`), `esi = [0x12588E8]`, `call 0x9B7610` with `[esi+0xB4]` (same helper as Production), then tick timer `[ebx+0x30] = x − x/17 + 10` (magic `0x78787879`, `sar 3 / shl 4 / add`), then the shared date idiom below. Month cache `[ebx+0x64]` (file `0x454E70`): heavy phases run only on day-change (High). Brain `0x855A90` (SEH, file `0x454E90`): country resolve via `[0x12587E4]`; uncivilized gate `[eax+0x12D0]` → 2× `0x855ED0` on sub-objects `+0x850/+0x860` (file `0x4552D0`); civilized path: `0x855BB0` two-count compare (`0x542BC0` vs `0x543470`, files `0x141FC0/0x142870`) + symmetric flag-ordered sub-phases `0x855D10` (enactor loop, file `0x455110`; validators `0x525D90`+ctor `0x591BE0` id `0x971` vs `0x5262C0`+ctor `0x5910D0` id `0x970`) / `0x547100` / `0x547030` (table-fills `+0x58`/`+0x68`); gate `0x541B90` (bool arith predicate, file `0x140F90`) then order-ctor `0x588BB0` + queue dispatch. Main pass `0x856470` (SEH, file `0x455870`): `[ecx+0xBD0]` gate, `0x4D61D0` vector push-back, 3× factory name-builds `0x9747A0`→`0x974850` singleton, scored selection, enqueue via ctor `0x58D450` (id `0x638`). PhaseU `0x855ED0` uses validators `0x525A20`/`0x525BE0` (class 3/2). 27/27 byte claims verified.
- **Research** (`0x859610`): timer `[ecx+0x30] = 1` (runs every tick), then date idiom. Year-index cache `[ecx+0x68]` (file `0x458AD1`); on change resolves country, gates `[eax+0x4CC]==0` (file `0x458AEE`), calls brain `0x859710` (file `0x458AF8`). Brain (SEH, frame `0xA8`, file `0x458B10`): civilized gate `[eax+0x12D0]` → join `0x859D10` (file `0x459110`); state init via `0x8A8650` (file `0x4A7A50`); alloc `0x9C` via `0xAAE9AF` + `0x576FE0`/`0x57AB10` (global slot `[0x125EADC]`); snapshot `0x9BEEB0`; max-scan loop with virtual calls + `0x57A4C0`; filter/collect with predicate `0x569920` (date-gated, AL bool) and vector append `0xA513F0`; score math via `0xAC02A0`/`0xAC9F20` + float helpers `0x401000`/`0xB31C00`; vector commit via `0x7B94A0`; RNG/weighted pick via `0x9B7700` + inline xorshift + `idiv 0x270`; construct `0x48` via `0x58AD00`; cleanup with virtuals + 3× `0xAAE91B`. Function ends `0x859D24` (`ret 4`, file `0x459124`) — later calls (incl. `0x859EF0`) belong to the next function. 53/53 byte claims verified.
- **NationalFocus** (`0x853FC0`): SEH frame, timer `[ebx+0x30] = 1`, then date idiom; year gate `[ebx+0x68]` (file `0x45345A`), log build via `0x409350` with `ai_national_focus.cpp` strings; chained queries (`0x55DD40/0x4015B0/0x987D50/0x418E30/0x401280/0x987AC0/0xAAD52D`); teardown + `call 0x854620` (helper-A, file `0x453A20`); outer province loop (`[eax+0x1488]` gate), filter `0x563FB0` (eligibility predicate, file `0x1633B0`) then scoring `0x564770 = fcn.00564770` (file `0x163B70`, best-tracked); 2nd pass with `call 0x854920` (helper-B single-target picker, file `0x453D20`) + `0x584340` node ctor + virtuals. Execute ends `0x854616` (`ret`, file `0x453A16`). Helper-A re-runs scoring with `0x565B70`-fetched lists and `allmul/alldiv` fixed-point scaling. 55/55 byte claims verified.

Shared date→year-fraction idiom (all three + Production): `ecx = [game+0xB0C] − 0x29C55C0`, `/3` (magic `0x2AAAAAAB`), `cvtsi2sd`, `/ [0xE45930]` — and `[0xE45930]` reads `365.0` (file `0xA43F30` ✓), i.e. days→years. Remainder resolved against the month-length table at `[0xF1027C + i*4]` (with day-pairs at `+0xF10280` in Research/Focus).

## 4. Non-Plan-family AI classes

- `CAIStrategy`: vtable `0xE27B14`→real start `0xE27B18` (COL `0xE5BB7C`, file
  `0xA26114`: `7C BB E5 00` ✓). Decoded slots (file `0xA26118`): 0=`0x84B810`,
  2=`0x85B460` (SEH, frame `0x22C`, file `0x45A860` ✓), 4=`0x85AE90` (SEH,
  id-dispatched evaluator: `cmp eax,0x720` @`0x85AEB6`, file `0x45A2B6` ✓,
  plus `0x336` arms), 7=`0x8321B0` (dtor thunk). Role narrowed 2026-10-01 to
  **consideration-ID dispatcher + demand/supply logging evaluator**: slot 4
  dispatches on small IDs (`0x720`/`0x336`/`0xCC`/`0x134`/`0x2A1`, files
  `0x45A2B6`/`0x45A2C7` ✓) into per-consideration object builders (`0x832170`,
  `0x85A180`, virtual slot `0xC`) storing the numeric outcome at `[edi+0x150]`
  (`mov [edi+0x150],eax` @`0x85AF5A`, file `0x45A35A` ✓); slot 2 funnels through
  the same ID space (`mov ecx,0x720` @`0x85B4E5`, file `0x45A8E5` ✓;
  `mov ecx,0x2A1`/`0x134` further down) around `yes/no/demand:/supply:` log
  lines (`0xDFBBD0/D4`, file `0x9FA1D0` = `yes\0…` ✓) built via `0xAAEE35`.
  Exact game meaning of the consideration IDs is still TBD.
- `CAIMTTHChance`: vtable `0xE2CECC` (COL `0xE60D98`; file `0xA2B4CC`=`C0 E2 8A 00` ✓).
  Decoded slots (file `0xA2B4CC`): 0=`0x8AE2C0` (scalar deleting dtor via `0x8AE2F0` +
  `0xAAE91B`, file `0x4AD6C0` ✓), 2=`0xA46A60`, 4=`0x8AEBD0` (id dispatch:
  `cmp eax,0x3BE` @`0x8AEBD6`, file `0x4ADFD6` ✓ → `lea [ecx+0x1C]` + `call 0x9A1CE0`,
  else `call 0x8AE8A0`), 7=`0x972880`. MTTH = mean-time-to-happen
  event chance evaluator; bodies beyond slot heads TBD.

## 5. `CAIRequest` family (8-slot vtables, `0xE27B50`–`0xE27C70`)

Concrete requests, each with own COL (e.g. `0xE27B50`→COL `0xE5BAB0`, file
`0xA2614C`: `B0 BA E5 00` ✓ = `CAIValueRequest`):

`Value 0xE27B50`, `Money 0xE27B74`, `ManPower 0xE27B98`, `Diplomat 0xE27BBC`,
`Merchant 0xE27BE0`, `Army 0xE27C04`, `Fleet 0xE27C28`, `Barrack 0xE27C4C`,
`Port 0xE27C70`. Base `CAIRequest` + `CAIUnitRequest` + `CAIBuildRequest` have
descriptors but NO COL/vtable → abstract (only constructed as derived).

## 5. `CAIEspionageMinister` — vestigial (Medium-High)

- Descriptor `.?AVCAIEspionageMinister@@` present (file `0xB15738` in `.data`:
  `2E 3F 41 56 43 41 49 45` ✓) but has **no COL and no vtable** — the only
  reference in the whole binary is a lazy-singleton getter at `0xC59E20`
  (`mov [ebp-4],0xF17D30`, file `0x859228`: `C7 45 FC 30 7D F1 00` ✓),
  via singleton allocator `0xAA8D10` (head file `0x6A8110` ✓; mallocs `0x18`,
  flag `[0xF1F838]`, instance `[0xF1F82C]`), stored to global `0x13F3624`.
- Getter has **zero callers** in `.text` (exhaustive `E8` scan); global
  `0x13F3624` is **write-only** (only ref is the `A3` store @`0xC59E38`).
- Verdict: the espionage minister is never instantiated nor consulted by game
  code in v3.04 — cut/vestigial system. (Sibling getter `0xC59E00` for the
  `PAV` pointer type, global `0x13F3628`, equally dead.)
