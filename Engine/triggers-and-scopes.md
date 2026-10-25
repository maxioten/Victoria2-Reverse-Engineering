# Triggers, scopes and effects

The script condition/effect machinery shared by events, decisions, CBs and everything else, and what
trigger evaluation can write.

Source: research of October 2026. Raw material in [data/](data/):
`trigger-classes.txt`, `trigger-vtables.txt`, `trigger-writescan-2026-10-11.txt`. Marks: **[C]** read in
the code, **[M]** measured.

## Summary

- Every trigger class has an RTTI name (`CTagTrigger`, `CIsAiTrigger`, ...); 236 exist. `Evaluate` is
  vtable slot 6 (`+0x18`): `bool __thiscall Evaluate(scope)`, `RET 4`.
- Every top-level block (`potential`, `allow`, `can_use`, event `trigger`, MTTH modifiers) is an
  embedded `CAndTrigger`: `{vftable, 0x18D, vector<CTrigger*> begin/end/cap}`, 0x1C bytes.
- Containers short-circuit in file order. Nothing is cached or reordered, so a block costs exactly
  "children evaluated until the first decisive one". Typical cost: tens of ns per block. **[M]**

## Containers **[C]**

| class | vtable | `Evaluate` | semantics | empty block |
|---|---|---|---|---|
| `CAndTrigger` | `0x00DF9994` | `0x008B8260` | false at the first false child | true |
| `COrTrigger` | `0x00E2FB70` | `0x008B88A0` | true at the first true child | false |
| `CNotTrigger` | `0x00E2FBA8` | `0x008B9240` | `NOT (a OR b ...)`: false at the first true child | true |

`CContextTrigger` (`0x00E2FBE0`, `Evaluate` `0x008B94B0`) is a scope change (`any_*`, `FROM = { }`,
`owner`, ...): it builds child scopes and evaluates its block in them.

## Scope (`CEventScope`, ctor `0x008A8650`) **[C]**

`CEventScope::ctor(this, parent)`, 0x48 bytes:

| offset | |
|---|---|
| `+0x00` | vftable `CEventScope` |
| `+0x08` / `+0x0C` | country reference (tag, index) |
| `+0x10` | province index (event province pass) |
| `+0x14` | pop pointer, initialised to the lazy `CNullPop` singleton (`0x01258A10`) |
| `+0x20` | the ctor's `parent` argument |
| `+0x24` | **THIS scope: initialised to the scope itself** |
| `+0x30` / `+0x34` | FROM reference |

The event code copies 0x48 bytes (`EventScope_Copy` `0x008A88D0`).

**A byte copy of a live scope is not a valid scope.** `+0x24` points at the original, so triggers that
go through THIS on the copy read the original's country. Any code that copies a scope must move fields
that point inside the source into the copy (or build the copy with the ctor). **[C]**

## Values **[C]**

- Country references (`tag = X`, `war_with = THIS`, ...) use the parser `0x008D3F50`: literal tag, `THIS`
  (token `0x405`) or `FROM` (`0x3DE`). The flags land at `+0x18` (THIS) and `+0x19` (FROM); the literal's
  country index at `+0x20` (tag chars at `+0x1C`).
- The generic int/float/bool parsers also accept `THIS`/`FROM` and set the same flags, even when the
  class's `Evaluate` ignores them.
- Bool values: `yes` = token `0x29F` (parser `0x008B93B0`). `CIsAiTrigger` (`0x00E30EE8`) keeps it at
  `+0x1C` and tests `world+0xAEC[country] == 0`.
- `has_country_flag` (`FUN_008CCB90`) looks the flag name up in the country's flag set (`country+0x1B0`,
  vt `+8`), a case-insensitive ternary search trie (`FUN_009E6C10`: node char `+4`, lo `+8`, hi `+0xC`,
  eq `+0x10`, value `+0`), one node per character. Each node is a separate allocation, so long flag names
  cost one cache miss per character. **[C][M]**

## Political reform selection

`CIssueGroupTrigger::Evaluate` at preferred VA `0x008C4DA0` compares the expected
option with a country's selected option. For category 2, group `+0x50` indexes
the option array **pointed to** by `CCountry+0x860`; group `+0x5C` is the category,
and option `+0x54` is its group. Parser `0x008C4A70` uses the issue-option registry
at `0x01258A48`, not a unit manager. See [Political reform selection](political-reform-selection.md)
for the static parser/effect paths, executable pin, and narrow GFM correlation;
no live reform transition or arbitrary-write safety is established.

## Classification of the 236 classes **[C]**

By decompiling every `Evaluate` and looking for `scope+0x24`, `scope+0x30/+0x34`, child evaluation or
scope construction: 174 scalar (read only the scope country, literals and globals), 20
country-reference, 40 pair-dependent, 2 helpers reviewed as scalar. Table: [data/trigger-classes.txt](data/trigger-classes.txt);
`Evaluate` / value-parser / block-parser slots of every class: [data/trigger-vtables.txt](data/trigger-vtables.txt).
No trigger class draws random numbers (there is no random trigger).

## Thread safety of trigger evaluation

What can an `Evaluate` write? From all 235 `Evaluate` functions plus `CDecision` slot 6, following
direct calls to depth 8 (688 functions), every write to an absolute address is one of: **[C]** ([data/trigger-writescan-2026-10-11.txt](data/trigger-writescan-2026-10-11.txt))

| kind | addresses | verdict |
|---|---|---|
| lazy singletons: `CNullPop` (`0x01258A10`), `g_cbManager`, `g_popTypeDb`, `0x012587EC`, `0x0125880C`, `0x01258A2C`, `0x01258A34`, `0x01258728`, `0x01258730`, `0x012586EC` | 12 | `if (g == 0) g = new ...`: created at load, no race in mid-game. The pop constructor (`0x00954A40`) behind `CNullPop` is the only path to a Mersenne Twister draw |
| "store the same value" helpers (`0x0125CE80`, `0x0125EA24`, `0x0131C99C`: `if (p == g) g = p`) | 3 | harmless |
| CRT: `operator new` handler, `atexit`, `NMSG`, `snprintf` buffer, `report_gsfailure` | ~40 | error paths, or internally locked |
| `ExceptionList` (`fs:0`) | 1 | per thread |

So, as far as direct calls go, trigger evaluation does not change game state. Not covered by the
static scan: virtual calls into non-trigger objects and writes through pointers.

## Effects **[C]**

`CEffect` blocks execute through vtable slot 11 (`+0x2C`): `__thiscall Execute(scope, arg2)`, **two**
stack arguments, `RET 0x8`. Ghidra's parameter count follows usage, not the convention: check the
`RET imm16` before hooking a virtual.

| effect | vtable | `Execute` |
|---|---|---|
| `CSetCountryFlagEffect` | `0x00E2AC88` | `0x008829E0` |
| `CClrCountryFlagEffect` | `0x00E2ACC0` | `0x00882A40` (flag name std::string at `+0x20`, country = `scope+0x0C`) |
| `CSetGlobalFlagEffect` | `0x00E2AD68` | `0x00882B60` |
| `CClrGlobalFlagEffect` | `0x00E2ADA0` | `0x00882BA0` |

## Region scope iteration

Preferred VA `0x00888BA0` (`CRegionScopeEffect::Execute`) receives `this` in `ECX`
and two stack arguments (`ret 8`): region `this+0x3C`, province list `region+0x8`,
filter `this+0x20`, child effect chain `this+0x8`. `CRegionScopeTrigger::Evaluate`
at `0x008C5DA0` receives `this` in `ECX` and one stack argument (`ret 4`), uses
region `this+0x1C`, and returns on the first matching province.

These are static mechanisms, not verified runtime attribution boundaries.
GFM's `any_land_province` names a custom region, not a native engine operator;
region cardinality does not equal a short-circuited visit count. See
[Script execution boundaries](script-execution-boundaries.md#region-scope-iteration-static-only)
for the executable/source pins, signatures, and limits.

## Keywords **[C]**

All script keywords get a token id in `Tokens_RegisterKeywords` (`0x00C381C0`), pattern
`MOV EDX,<string>; ...; MOV ECX,<id>`. To find a keyword: `grep -boa` the string in the exe, convert the
`.rdata` offset to a VA (+0x401A00), xref it. Per-class keyword maps: [data/cb-keyword-map.txt](data/cb-keyword-map.txt),
[data/decision-keyword-map.txt](data/decision-keyword-map.txt).
