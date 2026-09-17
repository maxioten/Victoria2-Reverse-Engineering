# `## Identification` 

```
`fcn.00564770` is the Victoria II AI scoring routine for choosing where to apply
a **national focus**. It calculates one signed, fixed-point score for one
province.
```

```
The strings and debug line numbers make that explicit:
```

- ``"Railroad score for ..."`` 

- ``"Promotion score for ..."`` 

```
- `"national_focus.cpp"`
```

- `debug line numbers `645` and `758`` 

# `### Arguments` 

```
The decompiler’s argument names are shifted by the return address. The actual
stack layout is:
```

```
```cpp
void fcn_00564770(
    CMapProvince* province,        // EDI, implicit "this"
    CNationalFocus* focus,         // [ebp+8]
    int32_t* out_score,            // [ebp+0x0c]
    CountryIndexPair* context      // [ebp+0x10]
);
```
```

```
`context` looks like a pair of country indexes/tags:
```

```
```cpp
struct CountryIndexPair {
    int32_t first;   // context[0]
    int32_t second;  // context[1]
};
```
```

```
Both are repeatedly used as indexes into the country-pointer vector at
`data.012587e4 + 4`.
```

```
`EDI` is conclusively a `CMapProvince*`:
```

- ``EDI+0x58` — province ID - `EDI+0x128` — apparently another province index` 

- ``EDI+0x12c` — owner country index` 

- ``EDI+0x188` — `CState*`` 

- ``EDI+0x1a8` — total population` 

```
- `EDI+0x1bc` — total clergy
```

```
The second argument is the national-focus definition:
```

- ``focus+0x54` — railroad component/magnitude` 

- ``[focus+0x7c, focus+0x80)` — vector of promoted pop types/effects` 

- ``focus+0xf4` — string data used by the zero-population eligibility check` 

```
The result is written through `out_score`; the value in `EAX` is not the
meaningful return value.
```

```
## Overall behavior
```

```
```cpp
void score_national_focus(
    CMapProvince* p,
```

```
    CNationalFocus* focus,
    int32_t* out,
    CountryIndexPair* context)
{
    int32_t score = 0;
    /*
     * Special rejection for an empty province.
     *
     * The helper at 0x00416db0 is an eligibility/membership test using
     * an empty string and focus->field_f4.
     */
    if (p->total_pops == 0) {
        if (focus->field_5c <= 0 || !focus_empty_pop_test(focus)) {
            *out = -100000;
            return;
        }
    }
    /*
     * Province-size factor.  Smaller provinces receive a larger factor;
     * very large provinces can make the final score negative.
     */
    int32_t pop_factor = population_size_factor(p->total_pops);
    /*
     * Railroad-specific national focus.
     */
    if (focus->railroad_value > 0) {
        CState* state = p->state;
        score = state->colony_status > 0 ? -100000 : 0;
        if (state->factory_count == 0)
            score -= 100000;
        if (score < 0) {
            *out = score;
            return;
        }
        // Internal fixed-point/thousandths scoring.
        score = 2000 + (state->factory_count / 2) * 1000;
        /*
         * Scan the province IDs in state+0x48 and count provinces where
         * the railroad focus can usefully apply.
         */
        int usable = 0;
        for (int province_id : state->province_ids) {
            CMapProvince* q = province_by_id(province_id);
            if (railroad_focus_applies_here(q, focus, context))
                ++usable;
        }
        if (usable == 0)
            score = -100000;
        log_ai(
            "Railroad score for %s in %s: %f",
            display_name(context),
            p->get_name(),
```

```
            score / 1000.0
        );
    }
    /*
     * Promotion/population national focuses.
     */
    for (PopTypeOrFocusEffect* t : focus->promotion_entries) {
        if (t->is_soldier) {
            score = soldier_score(p, t, context, pop_factor);
        }
        else if (t->is_bureaucrat) {
            score = administrator_score(p, t, context);
        }
        else if (t->is_clergy) {
            score = educator_score(p, t, pop_factor);
        }
        else if (t->is_industry_worker) {
            score = industry_worker_score(p, t, pop_factor, score);
        }
        else if (t->is_capitalist) {
            score = capitalist_score(p, t, context, pop_factor);
        }
        // AI avoids colonial states.
        if (p->state->colony_status > 0)
            score -= 100000;
```

```
        log_ai(
            "Promotion score for %s in %s: %f",
            display_name(context),
            p->get_name(),
            score / 1000.0
        );
    }
    *out = score;
}
```

```
The province-size calculation is the floating-point sequence at `0x0056485c–
0x00564908`: convert the population to a floating value, scale and offset it,
multiply by `1000.0`, take the ceiling, and then compute:
```

```
```cpp
pop_factor = 1000 - scaled_population_term;
```
```

```
The exact constants are stored in the binary at `0xe456c0`, `0xe45840`, and
`0xe45660`; the last is also the `1000.0` divisor used when printing the score.
```

```
## Promotion-type dispatch
```

```
The vector at `[focus+0x7c, focus+0x80)` is scanned at `0x00564c44`. Each entry
is tested with several byte flags. The branches are identifiable from the AI
defines they use:
```

```
| Flag test | Inferred pop-type category | Main define used |
```

- `|---|---|---|` 

- `| `entry+0x42 != 0` | Soldiers | `SOLDIER_WEIGHT`, `SOLDIER_FRACTION` | | `entry+0x3db != 0` | Bureaucrats/administrators | `ADMINISTRATOR_WEIGHT` |` 

- `| `entry+0x41 != 0` | Clergy/educators | `MAX_CLERGY_FOR_LITERACY`,` 

- ``EDUCATOR_WEIGHT` |` 

- `| `entry+0x50 != 0` | Factory/industry workers | `INDUSTRYWORKER_WEIGHT` |` 

- `| `entry+0x3da != 0` | Capitalists | `CAPITALIST_FRACTION` |` 

- `### 1. Soldier score — `0x00564d1b`` 

- `The routine:` 

`1. Obtains the owner country and province-level arrays:` 

- ````cpp owner = country_pointer_vector[p->owner_country_index];` 

- `current_value =` 

- `owner->field_1338[p->field_128] / owner->field_12e8[p->field_128]; ```` 

`2. Builds the desired soldier level from:` 

```
   ```cpp
   ai->SOLDIER_FRACTION
   ai->SOLDIER_WEIGHT
   ```
```

`3. Adjusts that target according to `country[context->second]->field_e40`:` 

- `value `2` adds the double constant at `0xe458f8`;` 

- `value `5` subtracts the double constant at `0xe45ed8`.` 

`4. Converts the relative shortfall into a score out of `1000`.` 

`5. Applies:` 

- ````cpp score = shortfall` 

   - `SOLDIER_WEIGHT * pop_factor` 

   - `/ 1000000;` 

```
   ```
```

```
So the AI strongly prefers provinces below its desired soldier share, with
additional preference for smaller provinces.
```

```
### 2. Bureaucrat/administrator score — `0x00564ec3`
```

```
This path calculates:
```

- `a province/state population share;` 

- `a country metric obtained through `fcn.00532ea0`;` 

- `the ratio between two such country metrics; - and finally:` 

```
```cpp
```

```
score = share * country_ratio * ADMINISTRATOR_WEIGHT / 1000;
```
```

```
The complicated shifts and `alldiv/allmul` calls are fixed-point arithmetic
around that basic operation.
```

```
It then has two notable adjustments:
```

```
```cpp
if (score < threshold_from_0xe458f8)
    score *= 10;
```

```
and:
```

```
```cpp
if (owner->field_be4 == p->province_id)
    score *= 10;
```
```

```
The second test is effectively a capital-province bonus. The colony penalty is
applied later at `0x0056569f`.
```

```
### 3. Clergy/educator score — `0x00565106`
```

```
This is the clearest branch.
```

```
It compares the province's clergy percentage with:
```

```
```cpp
defines.pops.MAX_CLERGY_FOR_LITERACY
```
```

```
The shortfall is normalized to a `0..1000` scale and then multiplied by:
```

```
```cpp
defines.ai.EDUCATOR_WEIGHT
pop_factor
```
```

```
Conceptually:
```

```
```cpp
clergy_shortfall =
    MAX_CLERGY_FOR_LITERACY - current_clergy_percentage;
raw_score =
    1000 * clergy_shortfall / MAX_CLERGY_FOR_LITERACY;
score =
    raw_score
    * EDUCATOR_WEIGHT
    * pop_factor
    / 1000000;
```
```

```
Thus a province far below the optimal clergy percentage receives a high
educator-focus score.
```

```
### 4. Industry-worker score — `0x00565254`
```

```
This branch examines factories in the province's state.
```

```
For each factory:
```

```
```cpp
for (factory = state->factory_list_head;
     factory;
     factory = factory->next_factory_in_state)
{
    if (factory->level >= 11)
```

```
        continue;
```

```
    if (factory->is_closed)
        continue;
    ...
}
```
```

```
The factory fields match the known `CStateBuilding` layout:
```

```
- `+0x020` — level
- `+0x188` — closed flag
- `+0x224` — next factory in state
```

```
It then walks the building type's employee records, using the known 32-byte
`CEmployee` layout. Records whose pop type matches the focus target contribute:
```

```
```cpp
```

```
employee_shortage =
    desired_employees - currently_employed_employees;
```

```
The shortage is transformed through the floating-point ceiling/rounding sequence
and multiplied by the previously converted:
```

```
```cpp
INDUSTRYWORKER_WEIGHT
```

```
The accumulated shortage is finally combined with the incoming score:
```

```
```cpp
score =
```

```
    (incoming_score + industry_worker_shortage)
    * pop_factor
    / 1000;
```
```

```
In short, this branch asks: **“How many more workers of this type could the
state’s open factories employ?”**
```

```
### 5. Capitalist score — `0x00565450`
```

```
The capitalist branch compares the current capitalist presence with:
```

```
```cpp
```

```
defines.ai.CAPITALIST_FRACTION
```
```

```
It uses province/country arrays at offsets `0x1338` and `0x12e8`, normalizes the
difference, and applies the usual population factor.
```

```
It then applies several AI policy checks:
```

```
```cpp
CCountry* target_country =
```

```
    country_pointer_vector[context->second];
```

```
if (!target_country->is_civilised)
```

```
    score -= 100000;
```
```

```
A plurality-like value from `province+0x1a8` is compared against a rounded
threshold:
```

```
```cpp
if (province_value < threshold)
    score -= 100000;
```
```

```
Finally, a state with fewer than one factory/building is penalized unless the
province is the owner’s capital:
```

```
```cpp
if (p->state->factory_count < 1 &&
    owner->field_be4 != p->province_id)
{
    score -= 100000;
}
```
```

```
The ordinary colonial-state penalty is then applied.
```

```
## Important control-flow detail
```

```
The promotion vector is **not treated as a maximum or sum**.
```

```
Each case assigns a new value to the local score variable. The industry-worker
case adds its shortage to the score that was already present, but there is no
general:
```

```
```cpp
score += contribution;
```
```

```
or:
```

```
```cpp
score = max(score, contribution);
```
```

```
Therefore, if a focus contained multiple promotion entries, the result would be
order-dependent. In normal focus data, a promotion focus has one relevant pop
type, so each call effectively produces one final score.
```

```
## Arithmetic and boilerplate
### Score units
```

```
The score is internally scaled by `1000`:
```

```
```cpp
0xfffe7960 == -100000   // printed as -100.0
0x000186a0 ==  100000   // printed as  100.0
```
```

```
The debug paths divide by the double at `0xe45660`, effectively `1000.0`, before
logging.
```

```
### Fixed-point arithmetic
```

```
Patterns such as:
```

```
```asm
shld edx, eax, 0x0f
shl  eax, 0x0f
...
push 0x01f40000
call flirt.alldiv
```
```

```
are ordinary 64-bit fixed-point operations. The game’s common fixed-point
representation is:
```

```
```cpp
real_value = stored_int64 / 2^15;
```
```

```
`flirt.alldiv` and `flirt.allmul` are MSVC 64-bit division/multiplication
helpers.
```

```
The repeated pattern:
```

```
```asm
lea  edx, [eax+0x189373]
cmp  edx, 0x39580d
jnbe slow_64bit_path
imul eax, eax, 0x3e8
```
```

```
is just an overflow-safe signed `x * 1000`.
```

```
### Logging
```

```
`data.012586d7` gates AI logging. When enabled, the routine constructs the
strings:
```

```
```text
Railroad score for <context-name> in <province-name>: <score / 1000>
Promotion score for <context-name> in <province-name>: <score / 1000>
```
```

```
The apparent string construction and deletion around `0x564a79` and `0x565701`
is temporary `std::string`/formatting boilerplate, not scoring logic.
```

```
### Lazy global allocation
```

```
The code around `data.0131bb34` lazily creates a `0x188`-byte object using
`ctor_with_MTTH`, replacing any previous global instance. It is a shared
lookup/scratch object used by the scoring calculations, not part of the final
result.
```

```
## Condensed source-level reconstruction
```

```
```cpp
void calculate_focus_score(
    CMapProvince* p,
    CNationalFocus* focus,
    int32_t* out,
    CountryIndexPair* context)
{
    int32_t score = 0;
```

```
    if (p->total_pops == 0 &&
        (focus->field_5c <= 0 || !focus_empty_pop_test(focus))) {
        *out = -100000;
        return;
    }
```

```
    int32_t pop_factor = small_province_bonus(p->total_pops);
```

```
    if (focus->railroad_value > 0) {
        CState* s = p->state;
        score = s->colony_status > 0 ? -100000 : 0;
        if (s->factory_count == 0)
            score -= 100000;
        if (score >= 0) {
            score = 2000 + 1000 * (s->factory_count / 2);
            if (!has_usable_railroad_province(s, focus, context))
                score = -100000;
        }
```

```
        log_railroad_score(context, p, score);
    }
    for (auto* t : focus->promotion_entries) {
        if (t->soldier_flag)
            score = soldier_shortfall_score(p, context, pop_factor);
        else if (t->bureaucrat_flag)
            score = administrator_score(p, context);
        else if (t->clergy_flag)
            score = clergy_shortfall_score(p, pop_factor);
        else if (t->industry_worker_flag)
            score = factory_worker_shortfall_score(
```

```
                        p, t, pop_factor, score);
        else if (t->capitalist_flag)
            score = capitalist_shortfall_score(
                        p, context, pop_factor);
        if (p->state->colony_status > 0)
            score -= 100000;
```

- `log_promotion_score(context, p, score); }` 

```
    *out = score;
}
```

```
In one sentence: **it rejects unusable/empty or colonial locations, gives
railroad focuses a score based mainly on industrialized states, and scores
promotion focuses according to how far the province is below the AI’s desired
soldier, bureaucrat, clergy, factory-worker, or capitalist level, with a bonus
for smaller provinces.**
```

