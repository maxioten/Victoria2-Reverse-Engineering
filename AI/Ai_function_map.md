# AI Function Map — full inventory (phase 2)

> One-line role per function from 25-insn entry windows. Entry bytes in ledger (phase-2 goals).
> `known` = documented elsewhere; `shared` = non-AI helper; `trampoline` = tiny forwarder; `body` = full body disassembled, role body-grounded (phase 3).
> Per-function body records (bounds, calls, strings, consts, role) live in [`bodies/`](bodies/) — 367 entries across 4 region files. Roles are agent-written from full-body disasm and spot-checked, not individually re-verified: treat them as guided pointers, re-verify any single role before building on it.
> Role verification 2026-10-01: every `mapped` role semantically re-verified against full-body disasm (diplomacy 24, army 111, ministers 76, king-peace 98 — CONFIRM or CORRECT with byte receipts, corrections applied). `known`/`shared`/`trampoline` rows by construction. Ledger holds the discriminator receipts.
>
> Independent cross-check (2026-10-01, `tools/vic2_smda_check.py`, SMDA 4.9.0): all 367 entries match an SMDA function start exactly; 150/150 disputed call targets verified as real `E8`s (SMDA outref gaps, zero hallucinations); 23 end-bounds corrected where the agent range swallowed padding + a trailing getter/next-fn head (ledger: "SMDA cross-check end-bound corrections"); 20 ranges kept with `smda_note` (SMDA coverage shorter, no interior ret+prologue split found).


## Army (0x820000-0x830000) — 132 functions

| VA | Status | Role |
|---|---|---|
| `0x820370` | body | Scaled per-country troop-requirement estimator; 64-bit divide chain, 0x3E8 clamps |
| `0x8204c0` | body | SEH node factory: mallocs/stamps country-context links via 0x4DADA0/0x4DC340 (inference) |
| `0x8205c0` | body | Scaled country-force valuator; 64-bit + float pipeline, feeds 0x820760 rollup |
| `0x820760` | body | Grand per-country mobilization aggregator; calls valuators 0x8205C0/0x820370, float gates |
| `0x820df0` | body | Cross-minister dispatch sweep; walks country table, invokes 0x841640-0x843B90 executors |
| `0x821190` | body | Dual request-packet builder with retry loops; random gate via 0xAB047B (inference) |
| `0x821510` | body | Leaf list annotator: writes node +0xA0 from area head, else zero |
| `0x821570` | shared-helper | Shared map/set container helper; alloc/find/insert, not army-specific |
| `0x821640` | shared-helper | Shared recursive quicksort partition over dword arrays |
| `0x821720` | shared-helper | Shared sort driver; median pivot with comparator 0x81DEC0 |
| `0x8218c0` | shared-helper | Shared sort splitter; delegates element moves to 0x821B20 |
| `0x821970` | shared-helper | Shared heap-adjust routine; comparator test plus copy-back |
| `0x821a10` | shared-helper | Shared tiny-range sorter with small-group fast path |
| `0x821a60` | shared-helper | Shared merge routine; block move via 0xAAE480 |
| `0x821b20` | shared-helper | Shared comparator-driven conditional element swap |
| `0x821b80` | shared-helper | Shared heap sift-down; span copy via 0x821BF0 |
| `0x821bf0` | shared-helper | Shared pure 64-bit range add/sub over stat blocks |
| `0x821d10` | body | Plan-state reset; zeroes +0x78-0x84, sets +0x30/+0x3C, reseeds evaluators |
| `0x821dc0` | body | Naval-brain Execute (CAIAdmiral, see movement-doc 7); 0x5CC3E0 gate, +0x68 sweep |
| `0x822100` | body | Strength-halving seeder plus virtual-gated list census; writes +0x78/+0x7C (FF D0 gated) |
| `0x822300` | body | Range compaction; memmove live span, fix +0x88/+0x8C bounds |
| `0x8223a0` | body | Army-list intake; per-stack eval contexts, area checks, readiness wrappers |
| `0x822cf0` | body | Guarded single-stack evaluation wrapper around 0x8268D0 |
| `0x822e40` | body | Province-target resolver; +0x5C chain walk, score 0x825380, wrap 0x825460 |
| `0x822fa0` | body | List filter; skips empty/busy nodes, dispatches 0x827410 or 0x822E40 |
| `0x8230a0` | body | Plus-0x68-list evaluation sweep; per-node wrapper 0x8255A0, area gate |
| `0x823370` | body | Per-country work driver; farms items to evaluator 0x823890 |
| `0x823890` | body | Scored candidate evaluator; float gates 10000/750.5, request build, wrap 0x8255A0 |
| `0x823d90` | body | Iterator feeding +0xA8 nodes to worker 0x823E70 |
| `0x823e70` | body | Bulk candidate materializer; table sweep, area query 0x48FEE0, wrap 0x8255A0 |
| `0x824650` | body | Gated force classifier; tier gate +0x84, class probes, float predicates |
| `0x824ab0` | body | Two-phase scorer; probe 0x824C10, vectorize 0x49B7F0, finalize 0x825A50 |
| `0x824c10` | body | Pure adjacency scorer; magic-divide neighbor loop, float rollup |
| `0x824e80` | body | Per-item loop; area check 0x4C3E20 then score via 0x824AB0 |
| `0x824f30` | body | List scorer; walks +0xAC nodes probing 0x824C10 |
| `0x825040` | body | Plus-0x68-list find-or-link node helper via 0x5F2AE0 |
| `0x825070` | body | Float-threshold predicate (750.5) over +0x90 list; boolean out |
| `0x825140` | body | Count predicate; true when >=4 nodes carry +0x34 class 6 |
| `0x825210` | body | Float-capped counter over +0x90 list; returns count |
| `0x8252b0` | body | Span-to-vector builder; maps range via 0x826F50, packs 0x49B7F0 |
| `0x825380` | body | Country-record fetch plus validate via 0x50E450/0x4A0E80 |
| `0x825460` | body | Eligibility-gated wrapper; gate, alloc, attach 0x5DF690, finalize pair |
| `0x8255a0` | body | Full eval-wrapper pipeline; gate, attach, score 0x827410, register |
| `0x825810` | body | Guarded +0x68 sweep with indexed virtual dispatch per node |
| `0x825a50` | shared-helper | Vector append/grow with fatal overflow guard; shared helper |
| `0x825b60` | body | SEH guard leaf around 0x57AAB0 accessor |
| `0x825bd0` | body | Save-serializer piece; field write 0x9A63F0 plus 0xAB111B (corrected 2026-10-01) |
| `0x825c90` | body | Registry-id assign plus virtual +0x18 dispatch |
| `0x825cf0` | body | Four merged vtable-slot stubs incl +0x3C CanExecute and 0xE26178 getter |
| `0x825d70` | body | Plus-0x54-list find-or-link helper via 0x5F2AE0 |
| `0x825da0` | body | Plus-0x54-list node allocator; links result at +0x58 |
| `0x825df0` | body | Plus-0x148-list node allocator; links result at +0x14C |
| `0x825e50` | body | Struct constructor; vtable 0xE3A544, seeds fields from globals |
| `0x825ec0` | body | Polymorphic +0x44-list drain via virtual +0x120; teardown walk |
| `0x826010` | body | Readiness-gated fan-out; virtual probe, +0x3C gate, worker trio |
| `0x826290` | body | List teardown; frees nodes, zeroes +0x54/+0x58/+0x5C header |
| `0x826350` | body | Plus-0x54 find with virtual +0x128 notify; null-safe |
| `0x8263c0` | trampoline | Virtual-tail trampoline; jumps [vtable+0x120], no ret |
| `0x8263d0` | body | Guarded virtual pair; probe +0x118, commit +0xC4 on match |
| `0x826400` | body | Plus-0x48-list node allocator; links result at +0x44 |
| `0x826450` | body | Plus-0x44 find-or-link with virtual +0x24 notify |
| `0x8264c0` | shared-helper | Shared pure list-membership predicate; returns boolean |
| `0x826530` | body | Gated stat-compare worker; virtual gate plus threshold math |
| `0x826670` | body | Virtual +0x19C probe then +0x148 append via 0x825DF0 |
| `0x8266a0` | body | Type-6 virtual aggregator over paired lists via 0x84F9D0 |
| `0x826780` | body | Type-7 virtual aggregator; twin of 0x8266A0 |
| `0x826860` | body | Float-param setter chain; +0x3C-gated virtual setters |
| `0x8268d0` | body | Eligibility-gated target evaluator; province probes plus save-write |
| `0x826aa0` | body | Multi-stage gated worker; delegates core scoring to 0x826D20 |
| `0x826c40` | body | Thin SEH wrapper; runs 0x826AA0, folds via 0x849E90 |
| `0x826cb0` | body | Arg-variant wrapper of 0x826C40 pattern; three stack args |
| `0x826d20` | body | Gated scorer core; virtual +0x1A4/+0x1B4 loops, 0x5CC3E0 gate, 0x4A81B0 probes (tail +0x2238 routine @0x826F50 excluded) |
| `0x826f90` | body | Pure virtual float accumulator over list; zero-seeded |
| `0x8271d0` | body | Twin float accumulator; alternate seed slot |
| `0x827410` | body | Vector-batch builder; alloc/fill loops with fatal-overflow guard |
| `0x8279e0` | body | Plus-0x68-swap setter with probe plus registry id |
| `0x827a90` | body | Float comparator on +0x6C fields; returns 1.0/0.0 |
| `0x827ad0` | body | Plus-0x54-membership boolean test |
| `0x827b10` | body | Probe-and-append via virtual +0x19C plus 0x825DF0 |
| `0x827b50` | body | Plus-0x54 find-or-link sibling of 0x825D70 |
| `0x827ba0` | body | Four merged thunk tails: +0x19C/+0x190 dispatchers, +0xAC accessor, 0xC stub |
| `0x827c00` | body | CAIArmy constructor; vtable 0xE26374, zero +0xAC-0xF4, +0xDC target |
| `0x827ca0` | body | CAIArmy scalar destructor; cleanup 0x827CD0 plus conditional free |
| `0x827da0` | body | Plan reinit seeder; stamps table ref plus flags +0x30/+0x3C |
| `0x827df0` | body | Plan refresh; rebuild wrapper 0x82E780, save, re-evaluate 0x82D8A0 |
| `0x827f30` | body | Plus-0xCC-list drain with +0xD4 countdown |
| `0x828030` | known | previously documented; skipped per brief |
| `0x828060` | known | previously documented; skipped per brief |
| `0x828320` | known | previously documented; skipped per brief |
| `0x828550` | body | Master plan executor; threat-gated branch switch over evaluators plus commit |
| `0x828ab0` | body | Dual-gate comparator; two virtual-gated probes, greater-or-equal verdict |
| `0x828bb0` | body | Head-stack connectivity test via pathfinder 0x51B200 |
| `0x828c10` | body | Scored probe; hostile check 0x5DC7C0 plus float scale, SEH |
| `0x828e30` | body | Pure scorer core; +0xB4 loop with float accumulation |
| `0x828f90` | body | Registry-id assigner; virtual pair plus vector push |
| `0x8290f0` | body | Grand target-selection sweep; score/commit pipeline per candidate, +0xE4 flag |
| `0x829ab0` | body | Multi-stack coordinator; area scan, pathfinders, threat-gated commit via 0x82C1D0 |
| `0x829f70` | body | Quota-driven mobilization caller; pushes 100000-count into 0x82A4F0 |
| `0x82a4f0` | body | Adjacency muster; neighbor loop, hostile-strength gate, muster dispatch |
| `0x82a880` | body | Province-value sweeper; target-chain walk, scaled accumulation |
| `0x82aea0` | body | Grand force planner; multi-phase table optimization with float weights |
| `0x82c1d0` | known | previously documented; skipped per brief |
| `0x82c380` | body | Siege-state iterator; +0xEC army walk under +0x70 nonzero gate |
| `0x82c540` | body | Candidate-filter chain; score, dual pathfinders, predicate pair |
| `0x82c6e0` | body | Virtual-threshold predicate under +0xB4>=2 gate; float 0.33 |
| `0x82c7f0` | body | Bulk target collector; +0xDC sweep into 0x4B3C40 vectors |
| `0x82caa0` | body | Connectivity-gated target sweep; 0x51B040 gates plus vector fills |
| `0x82d0f0` | known | previously documented; skipped per brief |
| `0x82d340` | known | previously documented; skipped per brief |
| `0x82d8a0` | body | Primary-stack eval driver; 0x82DA70 accessor pair, 0x8268D0 eval, save |
| `0x82da90` | known | previously documented; skipped per brief |
| `0x82dc50` | body | Staged request builder; hash init, registry, fill 0x829090, commit trio |
| `0x82e190` | body | Variant request builder over +0x98 list; same commit trio |
| `0x82e4e0` | body | Target-link stamper; validate 0x826530 then link +0x1A8/+0x1B0 |
| `0x82e510` | body | Reset-and-link; zero target slots, +0xAC find-or-link |
| `0x82e560` | body | Readiness-gated validator returning boolean |
| `0x82e590` | body | Plus-0xBC-variant reset-and-link |
| `0x82e5d0` | body | Gated dispatch wrapper; ensure 0x82E780, score/muster branch, many callers |
| `0x82e780` | body | Lazy wrapper allocator on eligibility-fail path; attach 0x5DF690 |
| `0x82e800` | body | Match-gated pipeline; ensure, score, build on target match |
| `0x82e940` | body | Sibling-plan scalar destructor (vtable 0xE2657C); teardown via 0x825EC0 |
| `0x82e970` | body | Randomized tri-state dispatcher into diplomacy 0x831A60 and mega 0x82F430 |
| `0x82eab0` | shared | float order-param fill: [eax+0x10..0x6c]+stack args to [esi], fld const, tail-calls float RTL 0xb31c36, flag +0x28=1 |
| `0x82eb30` | shared | float order-param fill: [eax+0x10/+0x14/+0x38..0x44]+stack args to [esi], fld const, tail-calls 0xb31c36, flag +0x28=0 |
| `0x82ebc0` | shared | fld-based float compare helper tail-calling 0xb31c36 |
| `0x82ec40` | shared-helper | Shared pure 64-bit min/max selector; no calls |
| `0x82ece0` | shared | float helper over +0x20/+0x24/+0x14/+0x18 calling 0xb31c36 |
| `0x82eea0` | body | Scaled-delta computer with min/max fold via 0x82EC40 |
| `0x82ef70` | shared | fld-based float min/store helper calling 0xb31c36 over [esi+0x20/+0x24] |
| `0x82f0b0` | shared | fld-based float min/store helper calling 0xb31c36 over [esi+0x20/+0x24] |
| `0x82f2a0` | shared | fld-based float min/store helper calling 0xb31c36 over [esi+0x20/+0x24] |
| `0x82f430` | body | Grand force-budget evaluator; 64-bit rollups vs float thresholds, 0x8000 clamp |

## Diplomacy (0x830000-0x844000) — 61 functions

> Roles semantically verified 2026-10-01: 24/24 behavior roles CONFIRM (27 key-insn bytes in ledger).

| VA | Status | Role |
|---|---|---|
| `0x831a60` | body | Country-field scan over +0xE78/+0xE7C with 32M-scale fixed-point math (economy-related, inference). |
| `0x831e00` | shared | Map-node comparator via 0xAAE98B returning boolean; generic container helper. |
| `0x831e20` | shared | Intrusive list splice/unlink via pointer swaps only; generic container helper. |
| `0x831e80` | shared | Map lookup combining 0xAAE98B, 0x831F70, 0x832110; generic container helper. |
| `0x831f70` | shared | RB-map routine with 'map/set<T> too long' fault; generic STL helper. |
| `0x832170` | body | Inline holder initializer: vtable 0xE274E0, type 0x18D, '---' placeholder. |
| `0x8321b0` | body | CCancelWarSubsidiesAction (0x8C1) initializer cluster; embeds 0x8C1 ID getter. |
| `0x832240` | body | War-subsidies string-holder initializer (CANCEL_WARSUBSIDIES); embeds 0xD9 getter. |
| `0x832280` | body | CAskMilitaryAccessAction (0x8C6) command initializer; embeds 0x8C6 ID getter. |
| `0x832340` | body | CCancelAskMilitaryAccessAction (0x8C7) initializer; embeds 0xCD/0xCE/0x8C7 getters. |
| `0x832400` | body | CGiveMilitaryAccessAction (0x8C8) initializer; embeds 0x8C8 ID getter. |
| `0x8324c0` | body | CCancelGiveMilitaryAccessAction (0x8C9) initializer; embeds 0x8C9 ID getter. |
| `0x8325a0` | body | CAllianceAction (0x332) command initializer; embeds 0x332 ID getter. |
| `0x832660` | body | Alliance string-holder initializer (ALLIANCE); embeds 0xC5/0xC6/0xC7 getters. |
| `0x8326c0` | body | CCancelAllianceAction (0x8CA) initializer; embeds 0x8CA ID getter. |
| `0x832760` | body | Cancel-alliance string-holder (CANCELALLIANCE); embeds 0xC8/0xC9 getters. |
| `0x8327b0` | body | CDiscreditAction (0x8C2) factory initializer with game-clock stamp; called at 0x837DA5. |
| `0x832890` | body | Discredit string-holder initializer (DISCREDIT); embeds 0xDC getter. |
| `0x8328d0` | body | CExpelAdvisorsAction (0x8C4) factory initializer; called at 0x837C4C. |
| `0x8329b0` | body | Expel-advisors string-holder initializer (EXPELADVISORS); single-ret body. |
| `0x8329e0` | body | CBanEmbassyAction (0x8D4) factory initializer; called at 0x837B50. |
| `0x832ac0` | body | Ban-embassy string-holder initializer (BANEMBASSY); embeds 0xE8 getter. |
| `0x832b00` | body | CDecreaseOpinionAction (0x8B1) factory initializer; called at 0x837EFD. |
| `0x832be0` | body | CIncreaseRelationAction (0x8D5) initializer; embeds 0x8D5 ID getter. |
| `0x832c80` | body | Increase-relation string-holder (INCREASERELATION); embeds 0xE9/0xEA getters. |
| `0x832cd0` | body | CDecreaseRelationAction (0x8D6) initializer; embeds 0x8D6 ID getter. |
| `0x832d90` | body | Decrease-relation string-holder (DECREASERELATION); embeds 0xEB getter. |
| `0x832dd0` | body | Global special-modifier evaluator: strength queries plus per-node scoring; feeds opinion core. |
| `0x833410` | body | Date/modulus-gated list walker (0x8483F0, 0x9B7700 — corrected 2026-10-01); diplomatic-queue tick helper. |
| `0x833650` | body | CAIForeignMinister initializer: vtable 0xE274FC, game-clock stamp, float fields. |
| `0x8336c0` | body | Minister cleanup: installs vtable, runs 0x825EC0, conditional delete. |
| `0x8336f0` | body | Relation-list walker issuing virtual calls with 0x859D30 per-node updates. |
| `0x833930` | body | CAIForeignMinister::Execute master loop: daily 0x83DE00 then monthly 0x833A40. |
| `0x833a40` | body | Monthly strategic loop over countries; runs crisis 0x83B3D0 and diplo 0x83C7D0 passes. |
| `0x834150` | known | SKIP: base bilateral sub-scorer, fully documented in Ai_relations.md. |
| `0x836080` | body | Action resolver: scores candidate actions twice through dispatcher 0x83DB20. |
| `0x8362b0` | body | Float/divide numeric helper over relation fields; feeds sphere math. |
| `0x8363f0` | body | Sphere/influence master pass; walks sphere lists, calls hostile evaluator 0x837330. |
| `0x836e70` | body | Influence-strength evaluator: treasury/strength queries with scaled divides. |
| `0x837330` | body | Hostile influence-action evaluator; invokes Discredit/Expel/Ban/DecOpinion factories. |
| `0x838090` | body | Influence-action planning pass; builds holders, scores via 0x836080. |
| `0x8384d0` | body | Relation-action pass; stages relation/alliance-cancel commands, scores via 0x836080. |
| `0x8386e0` | body | Crisis/relation gate evaluator using 0x832CD0 initializer and war-manager helpers. |
| `0x838eb0` | known | SKIP: crisis intervention evaluator, fully documented in Ai_diplomacy_crisis_soi.md. |
| `0x83b3d0` | body | Great-power crisis tick: GP-gated, runs 0x838EB0 intervention and 0x843170 peace. |
| `0x83c7d0` | body | Diplomatic-action tick over relation lists; calls 0x83DE70 evaluator and 0x836080. |
| `0x83db20` | known | SKIP: command dispatcher core/switch, fully documented in Ai_relations.md. |
| `0x83de00` | body | Country tick-stagger gate: date hash selects per-country processing slot. |
| `0x83de70` | body | Peace-action (0x81E) evaluator: lookups, 0x64 compares, strength queries. |
| `0x83ec10` | known | SKIP: opinion-score core, fully documented in Ai_relations.md. |
| `0x841640` | known | SKIP: opinion wrapper (raw score), documented in Ai_relations.md. |
| `0x8416b0` | known | SKIP: persuasion-difficulty wrapper (50-score), documented in Ai_relations.md. |
| `0x841870` | body | Pair-score helper: base 0x834150 result plus global modifiers 0x832DD0. |
| `0x841900` | body | Call-ally (0x8CB) evaluator: base score plus civilized-gated modifier-list walk. |
| `0x8419c0` | known | SKIP: AskMilitaryAccess case function, documented in Ai_relations.md. |
| `0x842a00` | known | SKIP: CancelAskMilitaryAccess case function, documented in Ai_relations.md. |
| `0x842a50` | known | SKIP: GiveMilitaryAccess case function, documented in Ai_relations.md. |
| `0x8430d0` | body | Cancel-give-military-access (0x8C9) evaluator: returns 50 minus AskMilAccess score. |
| `0x843170` | known | SKIP: peace-offer evaluator, documented in Ai_diplomacy_crisis_soi.md. |
| `0x843a10` | body | Crisis-offer (0x9FA) evaluator: runs 0x838EB0, returns 100 by side comparison. |
| `0x843b90` | known | SKIP: peace sibling scorer, fully documented in Ai_diplomacy_crisis_soi.md. |

## King/Peace (0x844000-0x852000) — 98 functions

| VA | Status | Role |
|---|---|---|
| `0x844050` | body | King query helper: const 0x3E8 + [esi+0x10]/[esi+0x14] pair into 0x834150. |
| `0x844140` | body | Variant of 0x844050: same 0x834150 call with 0x3E8, negated result. |
| `0x844210` | body | Tag-gated strategic scan: 0x85FA60 gate on +0x364 handle, +0xCF8/+0xCFC war gates, minister-table fan-out. |
| `0x845ad0` | body | SEH relation-row orchestrator driving peace-text builders + probe 0x846C40; asserts ai_foreignminister.cpp. |
| `0x8465a0` | body | Peace-text buffer init: 0x8A8650 x2, stages +0x18/+0x1C/+0x20/+0x24 fields. |
| `0x846830` | body | Peace-text buffer init variant: 0x8A8650 x2 plus consts 0x2D2D2D/0xADC. |
| `0x846990` | body | Bounded index loop over +0xDA8/+0xDAC with tag lookups via 0x93C7C0/0x936FC0/0xAC9F20. |
| `0x846a70` | body | Peace-text buffer init variant: 0x8A8650 x2 plus 0x846990 index loop. |
| `0x846c40` | body | Switched range probe over +0x9D8/+0x9DC elements (jump table @0x847A64); refs europe/africa. |
| `0x847b60` | body | Sorted-merge walker over [ecx+0x48/0x4C] lists; computed jump table @0x8483D8. |
| `0x8483f0` | body | Indexed-table guard (+0xAEC/+0xAF0/+0xB0C), xmm-zero early return; no calls. |
| `0x848540` | body | War-state branch on [edx+0xE4C] with +0xE44 object fetch; no calls. |
| `0x8485f0` | body | Peace lookup via 0x92F630 on +0xBE8 object; posts 0xAC02A0/0xAC9F20. |
| `0x8486b0` | trampoline | trampoline forwarder to 0x848830 (packs edx/eax/ecx counts + pushes args) |
| `0x8486e0` | body | Recursive range dispatcher (self-call) fanning to 0x848930/0x8491A0/0x8490B0/0x849120. |
| `0x848830` | body | Mid-size range splitter dispatching 0x848B40/0x8494D0/0x849310/0x849460 (+self). |
| `0x848930` | body | Binary-split setup via 0x849000 probe plus 0x849680 comparator. |
| `0x848b40` | body | Recursive bisection step via 0x849240 plus 0x936FC0 row fetch. |
| `0x849000` | body | Upper-bound probe delegating to shared 0x849720 comparator. |
| `0x8490b0` | body | Count-from-span helper via 0x849680 plus 0x8497A0 loop. |
| `0x849120` | body | Two-probe copy/compare via 0x849680 plus 0x8497A0. |
| `0x8491a0` | body | Single-step advance compare via 0x849680 plus 0x849B60 tail block. |
| `0x849240` | body | Bisect core with +0xBE8/+0x34 peace-row fetch via 0x849810. |
| `0x849310` | body | Linear-scan setup via 0x936FC0 plus binary address calc 0x849C20. |
| `0x849460` | body | Small-span align check plus indexed peace-row calc via 0x849970. |
| `0x8494d0` | body | Range-equality early-out + 0x936FC0 lookup; embeds 0x849680 comparator entry + copy stub. |
| `0x849720` | body | Multi-probe merge/compare via shared 0x849680 comparator. |
| `0x8497a0` | body | Adjacent-pair loop compare via 0x849680 plus midpoint helper 0x849A60. |
| `0x849810` | body | Cross-table peace fetch (+0xBE8/+0x34) combined via 0x936FC0. |
| `0x849970` | body | Indexed peace-row address calc via 0x936FC0 plus 0x849C20. |
| `0x849a60` | body | Midpoint insert helper; tail-jmps shared 0x849680; owns 0x849B60 compare block. |
| `0x849c20` | body | Binary-search address calc via 0x936FC0 plus prologue-less micro-stubs. |
| `0x849d40` | body | Float clamp setter: max([ebp+8],0.0) stored to [ecx+0xC]; no calls. |
| `0x849d60` | body | Float-clamp ctor: clamps xmm0>=0 into [eax+0xC]; no calls. |
| `0x849da0` | body | Float-pair ctor (ret 8) plus two prologue-less accessor stubs. |
| `0x849e30` | body | List teardown via 0xAAE91B/0xAAEAC2 plus micro-getters (0xE276E0='King' vtable ref). |
| `0x849f50` | body | Linked-list find-or-null at +0x1DC via 0x5F2AE0. |
| `0x849f90` | body | Linked-list find-or-null at +0x1EC via 0x5F2AE0. |
| `0x849fd0` | trampoline | trampoline to 0x84af00 (moves edx=[ebp+8], eax=ecx, tail call) |
| `0x84a080` | trampoline | vtable-init wrapper: calls 0x84a0b0 then conditional 0xaae91b delete, returns esi |
| `0x84a150` | known | already documented — skipped (known) |
| `0x84a350` | trampoline | vtable-init wrapper: calls 0x84a390 then conditional 0xaae91b delete, returns esi |
| `0x84a390` | body | SEH array-ctor at +0x23C clearing slots, vtable 0xE27714. |
| `0x84a5c0` | body | Peace-plan builder: allocs/links condition nodes, 4x 0x859D30, runs 0x84ACA0 committer. |
| `0x84aa80` | body | Global-list unlink (4 lists) plus accumulator reset and army-list prune. |
| `0x84ac50` | body | King-armies matcher: walks [eax+0x214], vcall +0xCC, 0x4E9470 test per node. |
| `0x84aca0` | body | Matcher-then-commit driver: +0x7B4 context, 0x84AC50 per node, commits via 0x82C4D0. |
| `0x84af00` | body | Two-phase peace-gate latch (+0x23A/+0x23B) on tag/state/dirty checks; no calls. |
| `0x84af70` | body | King-armies membership test: vcall +0x104, walks [edi+0x214], +0x120 dispatch. |
| `0x84afd0` | shared | shared duplicate of 0x84af70: vcall +0x104 then [edi+0x214] list walk for ebx |
| `0x84b030` | trampoline | vtable thunk: jmp [eax+0x6c] where eax=[ecx] |
| `0x84b040` | trampoline | vtable thunk: jmp [eax+0x70] where eax=[ecx] |
| `0x84b050` | body | Dirty-flag setter for +0x238 with [eax+0x144] validation; no direct calls. |
| `0x84b0a0` | body | Dirty-flag setter for +0x239, same shape as 0x84B050. |
| `0x84b0f0` | known | already documented — skipped (known) |
| `0x84b5a0` | body | Peace-target linker: appends target to +0x200 list on tag match, latches 0x84AF00. |
| `0x84b690` | body | Slot-9 tick updater: 1/15-gated 0x851440, +0x1C8 accumulator, army sweeps, 8x 0x84EF30. |
| `0x84b810` | trampoline | init wrapper: calls 0x85a6f0 then conditional 0xaae91b delete, returns esi |
| `0x84b840` | body | Float-init plus list guard; tag-pair predicate via 0x51B040. |
| `0x84bd60` | body | SEH bounded pass over [esi+0x70/0x74]: REB-filtered rows, node lists, 0x851130/0x84B840 scoring. |
| `0x84c470` | body | SEH peace-text composer: 0xE276F0-format builders, 0x3E8-scaled posts; noreturn cold tail. |
| `0x84d1d0` | body | Rand-gated Execute helper chaining 0x84C470 composer plus 0x85FBC0 pair. |
| `0x84dfc0` | known | already documented — skipped (known) |
| `0x84e740` | body | Peace-row scan via +0xACC table (+0x110/+0x34 guard) and 0x48F070 area check. |
| `0x84e9f0` | body | Triple-posting scorer: 0x7D0/0x3E8-scaled 0xAC9F20/0xAC02A0 plus 0x4E9B90/0x7B94A0. |
| `0x84ef30` | body | Element applier: clears [eax+edi+0x234], walks [ebx+0xBC] via vcall. |
| `0x84f170` | body | Float-ordered row insert-or-flag: comisd on +0x6C pair, 0x9B3C80/0xAAE9AF paths. |
| `0x84f260` | body | Float-gated node factory (vcall +0x15C) delegating placement to 0x84F170. |
| `0x84f300` | body | Float-gated node factory (vcall +0x168) delegating placement to 0x84F170. |
| `0x84f3a0` | body | Float-gated node factory (vcall +0x174) delegating placement to 0x84F170. |
| `0x84f440` | body | Float-gated node factory (vcall +0x180) delegating placement to 0x84F170. |
| `0x84f4e0` | body | 0x18-alloc float-clamp node (kind 4) via 0x84F170 plus 0xAAE9AF. |
| `0x84f580` | body | 0x18-alloc float-clamp node (kind 5) via 0x84F170 plus 0xAAE9AF. |
| `0x84f620` | body | 0x14-alloc const-float node (kind 6) via 0x84F170 plus 0xAAE9AF. |
| `0x84f6b0` | body | 0x14-alloc const-float node (kind 7) via 0x84F170 plus 0xAAE9AF. |
| `0x84f740` | body | Float accumulator add on +0x1C8; no calls. |
| `0x84f7c0` | body | Float accumulator sub on +0x1C8; no calls. |
| `0x84f820` | body | Float accumulator sub on +0x1D0; no calls. |
| `0x84f850` | body | Float accumulator add on +0x1D4 with dirty flag 0x236; no calls. |
| `0x84f8a0` | body | Float accumulator sub on +0x1D4; no calls. |
| `0x84f8d0` | body | Float accumulator add on +0x1D8 with dirty flag 0x237; no calls. |
| `0x84f920` | body | Float accumulator sub on +0x1D8; no calls. |
| `0x84f950` | body | Predicate via 0x826530 plus dirty flag 0x238 setter. |
| `0x84f980` | body | Predicate via 0x826530 plus dirty flag 0x239 setter. |
| `0x84f9b0` | body | Equality predicate ([edx+0x324]==ecx); no calls. |
| `0x84f9d0` | body | List search at +0x13C via 0xAAE9AF/0x9B3C80. |
| `0x84fa90` | body | Guarded list walk at +0x13C/+0x74 via 0x5F2AE0. |
| `0x84fb30` | body | 0x10-alloc link node via 0xAAE9AF on [esi+0xAC] miss. |
| `0x84fbb0` | body | SEH 0x60-alloc builder (push-1 variant) via 0xAAE9AF plus 0x57DB30. |
| `0x84fc60` | body | SEH 0x60-alloc builder (push-0 variant) via 0xAAE9AF plus 0x57DB30. |
| `0x84fd10` | body | Tag-gated node factory: 0x9C1D40 resolve, 0x5CC3E0 eligibility, 0x5F2AE0 dedup, 0x5E1EE0 finalize. |
| `0x84fea0` | body | SEH counted-divide scan with REB filters; 0x10-alloc via 0xAAE9AF. |
| `0x8500a0` | known | already documented — skipped (known) |
| `0x850b20` | body | Dual-path rebel-aware target dispatcher: 0x48E120 plus 0x4A0E80 per tag source. |
| `0x851130` | body | Tag-chain walker with +0xEC vcall loop; allocs via 0xAAE9AF, predicate 0x51B040. |
| `0x851440` | body | SEH army-context loader (+0x7B4) feeding 0x84E9F0 scorer and 0x827C00. |
| `0x851ad0` | body | Ratio/divide helper: +0x1DC node, scaled index via 0x9C1D40 plus 0x853DB0. |
| `0x851bd0` | known | already documented — skipped (known) |

## Ministers (0x852000-0x85B000) — 76 functions

| VA | Status | Role |
|---|---|---|
| `0x852a00` | body | SEH per-country record builder via 0x826AA0/0x849E90, stores slot 0xA0. |
| `0x852c20` | body | Float-scored target evaluator; slot-0x15C compare, 0x3C-gated 0xE8/0xF0/0xF4 chain. |
| `0x852cf0` | body | Twin float evaluator on slot 0x168 with 0x3C gate and 0xE8/F0/F4/0x1F0 chain. |
| `0x852de0` | body | Twin evaluator, slot 0x174 variant of same float-compare shape. |
| `0x852ed0` | body | Twin evaluator, slot 0x180 variant of same float-compare shape. |
| `0x852fc0` | body | Score-table fill pass into static table 0x13F2010 via float merges. |
| `0x8534f0` | body | Best-score merge pass over triple float tables 0x13F1CF0/CF8/D00. |
| `0x853b30` | body | Guarded virtual-dispatch evaluator on slot 0x1C0 via 0x826720. |
| `0x853c80` | body | Twin guarded evaluator on slot 0x1CC via 0x826800. |
| `0x853db0` | shared | Generic intrusive-list clearer freeing nodes via 0xAAE91B. |
| `0x853e20` | body | Ordered insert into [edx+0xC]-keyed list; fallback 0x9E6CC0; 0x10-nodes. |
| `0x853ef0` | body | CAINationalFocus scalar dtor; frees +0x6C chain, base 0x825EC0. |
| `0x853f40` | body | Minister init: virtual-0xF0 probe, flag +0x3C, queue id 0x21, RNG timer. |
| `0x853fc0` | known | NationalFocus Execute: day-gated province scoring loop and helpers. |
| `0x854620` | known | NatFocus helper-A: list-driven rescoring with fixed-point scaling. |
| `0x854920` | known | NatFocus helper-B: single-target picker plus node construction. |
| `0x854b80` | shared | Vector grow with 0x15555555 overflow guard; 12-byte copy helper. |
| `0x854c60` | shared | Introsort dispatcher on 12-byte elements; insertion, heap, partition paths. |
| `0x854d90` | shared | Quicksort partition driving comparator 0x855040 over 12-byte elements. |
| `0x855000` | shared | 12-byte block copy loop, call-free. |
| `0x855040` | shared | Range-size dispatcher (threshold 0x28) onto step routine 0x855370. |
| `0x855100` | shared | Heap-build pass over 12-byte elements via sift 0x855490. |
| `0x8551f0` | shared | Heap-extract loop over 12-byte elements via step 0x855400. |
| `0x8552b0` | shared | Insertion sort on 12-byte elements, call-free. |
| `0x855370` | shared | Compare-swap step on 12-byte elements, call-free. |
| `0x855400` | shared | Sift-down step on 12-byte heap via primitive 0x855490. |
| `0x855490` | shared | Heap sift primitive with tripled-index addressing, call-free. |
| `0x855500` | shared | Float member setter: [ecx+0x6C] constant, [ecx+0xAC] argument. |
| `0x855520` | body | CAIMilitaryPlan scalar dtor; vtable 0xE27EB4, base 0x825EC0. |
| `0x8555a0` | body | Lookup-or-dispatch over [ecx+0xB0] list via 0x5F2AE0. |
| `0x8555f0` | trampoline | Delegating wrapper: uninventoried 0x855620 dispatch plus conditional free. |
| `0x855670` | body | Minister init: timer=1, flag +0x3C, queue id 0xF, RNG timer. |
| `0x855720` | trampoline | Always-true wrapper around 0x826530; returns 1. |
| `0x855740` | body | Guarded dispatch: [eax+0x144]==ecx then virtual-0xE8 plus 0x823890. |
| `0x855780` | body | Filtered enumerator via virtual-0x1B4 building records with 0x826AA0/0x849E90. |
| `0x855950` | body | CAIPoliticsMinister scalar dtor; vtable 0xE282D4, base 0x825EC0. |
| `0x855980` | known | Politics Execute: tick timer plus month-gated brain and main pass. |
| `0x855a90` | known | Politics brain: uncivilized gate plus civilized phase dispatch. |
| `0x855bb0` | body | Politics count fetch 0x542BC0/0x543470 plus flag-ordered sub-phase calls. |
| `0x855d10` | body | Politics sub-phase: validator pair plus order ctors, flag-ordered. |
| `0x855ed0` | body | Politics phase-U: scored table fill with validators 0x525A20/0x525BE0. |
| `0x856470` | known | Politics main pass: factory builds plus scored request enqueue. |
| `0x856930` | body | CAIProductionMinister scalar dtor; vtable 0xE284DC, base 0x825EC0. |
| `0x8569a0` | known | Production Execute: day gate plus six gated phase calls. |
| `0x8571a0` | body | Call-free integer scorer with multiply/divide scaling and validity gates. |
| `0x857430` | body | Allocator-backed candidate enumerator scoring each via 0x8571A0. |
| `0x857530` | body | Fixed-point scorer with allmul/alldiv and float conversion. |
| `0x8577b0` | body | Large candidate enumerator and scorer over +0xE44 lists with RNG. |
| `0x857e60` | body | Candidate validator scan: +0x9D8 deltas, +0xBE4, flag 0x2A checks. |
| `0x8580e0` | body | Per-candidate check with early exit; container plus fixed-point math. |
| `0x8582d0` | body | Per-unit validation on slot +0x78 via 0x8580E0; lazy singleton init. |
| `0x858460` | body | Slot-phase on +0x80 via setup 0x8577B0 and shared tail 0x4DA790. |
| `0x858560` | body | Twin slot-phase on +0x7C via setup 0x857E60; mirrored thresholds. |
| `0x858670` | body | Enumerator-pair phase with [ebx+0x6E] gate and 0x5827F0 build. |
| `0x8589b0` | body | Batched phase chaining 0x858D90, enumerators, and 0x8582D0 tail. |
| `0x858d90` | body | Capacity and delta precompute feeding batched phase 0x8589B0. |
| `0x859180` | body | Per-item type-switched loop over +0xE44 list on +0x244 dispatch. |
| `0x859560` | body | CAIResearch scalar dtor; vtable 0xE286C4, base 0x825EC0. |
| `0x859590` | body | Research init: flag +0x3C, queue id 0x20, RNG-derived timer. |
| `0x859610` | known | Research Execute: yearly gate into research brain 0x859710. |
| `0x859710` | known | Research brain: snapshot, scoring, weighted technology pick. |
| `0x859d30` | body | Indexed intrusive-list insert at static table 0x1318B20. |
| `0x859dd0` | body | Filtered-removal wrapper with predicate slot 0x1A8 over 0x859EF0. |
| `0x859e60` | body | Twin filtered-removal wrapper with predicate slot 0x1B8. |
| `0x859ef0` | body | Predicate-filtered list unlink plus node free via callback. |
| `0x859f80` | body | Unconditional list sweep with unlink plus node free. |
| `0x85a000` | body | Static slot-pair accessor at 0x1318C70 via 0x4C0FD0. |
| `0x85a090` | body | Twin static slot-pair accessor at 0x1318C80 via 0x4C0FA0. |
| `0x85a180` | body | Consideration outcome builder: id 0x18D, zero float, tag bytes. |
| `0x85a1c0` | body | SEH logging evaluator: log via 0x409350 plus object build. |
| `0x85a260` | body | SEH non-logging sibling evaluator: object build plus free. |
| `0x85a2e0` | body | Bulk table builder with alloc/fill loops and 0x1FF capacity. |
| `0x85a6f0` | body | Multi-field record assembler via 0x85AC70 and container append. |
| `0x85aa20` | body | Fan-out dispatcher over ten 0x85Bx sub-evaluators (plus 0x408ED0/0xAAE91B). |
| `0x85ac70` | body | Container-backed evaluator with fixed 0x1FF vector. |
| `0x85ae90` | body | Strategy consideration-ID dispatcher into per-ID object builders. |
