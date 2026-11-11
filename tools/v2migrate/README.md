# v2migrate — layout-A prototype (observe/bump-allocate relations)

A The Grand Loader plugin that implements layout A from
[`research/perf/experiments/relations-soa/`](../../research/perf/experiments/relations-soa/):
the single relation allocation site (`push 0xAC` / `call operator new` at
`0x005047F7`, the only caller of the relation constructor) is redirected to
a bump allocator over one preallocated block (683×683 slots of 176 bytes =
stride 0xAC rounded up so every slot stays 8-aligned). The constructor, the
vector `push_back`, and all readers then work unchanged with block pointers;
later growth (new nations) is covered automatically, and there is nothing to
free afterwards.

A tick hook (call to the daily tick at `0x00683AB1`) only observes: on the
first tick it logs country/relation counts.

With `migrate=0` (default) nothing is redirected except the observing tick
hook. With `migrate=1` the block is allocated at plugin init and the new
site is hooked, with fallback to the original `operator new` (logged) if
the block ever exhausts.

It does **not** change game logic: no loop is modified, the vector mechanics
(including growth reallocation of the pointer array) keep working. Live
matrix at 1837.1.1 is 272×272, growing on demand — which is why the bump
design replaced an earlier bulk-migration draft (a post-load pass would miss
relations created later).

## Safety basis

See the lifetime analysis, write sets and migration pre-check in the
experiment README. Short version: single construction path, objects never
freed individually, readers reload the vector base per access, no
child-to-relation back-pointer found. The fixed-save acceptance protocol
(same save hash, values, RNG over 30 days) is the backstop.

## Build

Needs an i686 Windows toolchain. Validated with pinned llvm-mingw
(`mstorsjo/llvm-mingw` 20261104, msvcrt flavor, local-only under
`tools/llvm-mingw/`; SHA-256 recorded in the PR; loads and hooks verified
in-game). `build.sh` uses it when present, else `i686-w64-mingw32-gcc`
(override with `V2MIGRATE_CC`).

```bash
./build.sh
# copy build/v2migrate.dll to <game>/mod/v2migrate/ and v2migrate.ini to <game>/mod/
```

Requires The Grand Loader (`dinput8.dll`) in the game directory.

## Output

Lines prefixed `[migrate]` in `the_grand_loader.log`:

```text
[migrate] v2migrate: tick_hook=1 new_hook=1 migrate=1
[migrate] first tick; migrate=1
[migrate] countries=272 relations=73984
```

The static `fallback_calls` counter exists for debuggers (one unused-variable
warning at build); a fallback would also be visible as heap (non-block)
pointers in the vectors.
