# Native console registration and debug commands

The console manager contains pointers to command descriptors. A descriptor
selects a native handler; the handler receives an argument collection and
returns a success/message result. A handler that compares its own argument
strings is not thereby the central dispatcher for every console command.

These findings target the English Windows Heart of Darkness 3.04 executable,
SHA-256 `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`,
12,294,656 bytes, x86, preferred base `0x00400000`. Addresses below are
**preferred-base VAs**. Object offsets use `+`; at runtime relocate a VA as
`loaded_base + (VA - 0x00400000)`.

## Registration boundary

The initializer at `0x00423990` receives the manager through EAX and retains
it in ESI. Its loop reads manager begin/end/capacity at `+0/+4/+8`, appends
four-byte descriptor pointers, and advances through a native descriptor table
by `0x4C` at `0x00423A38`. The table begins at `0x00F09740`.

At the epilogue site `0x00423A43`, ESI still holds the populated manager:

```asm
pop edi
pop esi
pop ebx
mov esp, ebp
```

This is the existing Smedley capture boundary, **not** a function entry or a
permission to retain the manager indefinitely. It supports reading the
registered command set within the checked lifecycle. The initializer and
descriptor stride are statically corroborated in the supported executable;
the capture site is cataloged as `verified-current`, not an independently
exercised registration/unregistration API.

## Descriptor and call records

| Record / extent | Fields | Evidence and limit |
| --- | --- | --- |
| Command descriptor, `0x4C` | Allowed byte `+0`; name pointer `+4`; alias count `+8`; three alias pointers `+0xC`; description pointer `+0x18`; handler pointer `+0x1C`; argument count `+0x20`; ten argument-name pointers `+0x24` | Current narrow Smedley layout; native table stride and the two descriptors below are statically corroborated. Do not infer ownership or permission-policy semantics from the field names. |
| Manager pointer-vector prefix | Begin/end/capacity `+0/+4/+8` | Native registration loop corroborates these three fields. The extra allocator word used in the implementation is not a separately verified native contract here. |
| Arguments, `0x10` | Begin/end/capacity pointers `+0/+4/+8`; allocator word `+0xC` | Current invocation layout. Elements are engine strings, not `char*` pointers; the debug handler computes the count using `0x1C`-byte elements. |
| Result, `0x20` | Success byte `+0`; engine-string message `+4` | Current invocation/result layout, not a complete ABI audit of every command handler. |
| Engine string, `0x1C` | Inline buffer/heap pointer union `+0`; length `+0x10`; capacity `+0x14`; allocator word `+0x18` | Current x86 representation; inline capacity `0xF`. Long-string storage, ownership and destruction must be reviewed at the specific boundary. |

The checked C++ compatibility type is a result returned by value from a
handler taking an argument record by reference. MSVC's x86 hidden return-buffer
convention matters: this is **not** `bool handler(const char*)`, and a raw
address cast does not establish a usable native ABI. Smedley's invocation
wrapper constructs a single inline engine-string argument; it does not prove
arbitrary argument vectors or safe cross-thread execution.

| Static descriptor | Registered name | Handler | Argument metadata |
| --- | --- | --- | --- |
| `0x00F0A2D4` | `tag` | `0x0041F720` | One argument, `country_TAG` |
| `0x00F0A748` | `debug` | `0x00420EB0` | One argument; description enumerates debug subcommands including `fow` |

These entries directly corroborate the names and handler pointers. `tag`
starts an asynchronous ownership/view transition: handler return is not proof
of completion. The wider tag-switch and observer lifecycle is outside this
console-layout note.

## Checked `debug fow` operation

`0x00420EB0` is the registered **debug command handler**. It accepts `fow` as
an argument, among other debug subcommands. This is narrower than the earlier
claim that it is the universal console dispatcher.

The supported binary supplies primary anchors:

| Site | Mechanism |
| --- | --- |
| `0x00422136` | Loads the string at `0x00DF2098`, which is `fow`, for comparison |
| `0x00422148` / `0x00422171` | Reads the fog-enabled byte at `0x00F092FB` |
| `0x0042217B` / `0x0042217E` | `SETE AL`, then stores AL to `0x00F092FB`: toggles zero/nonzero |
| Following block | Invalidates idler map-related state rather than merely changing the global byte |

Historical runtime correlation establishes `0x00F092FB = 0` as revealed map
and `1` as normal fog for the checked observer route. The checked caller finds
`debug` in the populated manager, requires the expected handler pointer and
signature, invokes it with the single inline argument `fow`, and reads back
the flag. It does not patch terrain/text rendering branches.

The older notes associate `fow` with `0x013F080C` and a renderer mirror. The
relationship between that rendering state and `0x00F092FB` is unresolved here;
do not equate the two or silently replace all rendering-state observations.
The registered handler and its direct toggle are established without that
relationship. Likewise, a disabling experiment does not establish a universal
dispatch ABI or prove every console command passes through `0x00420EB0`.

## Provenance and limits

Sources are Smedley's immutable
[mapping catalog](https://github.com/adrunkhuman/smedley_kernel/blob/a87832e6196168b6b6ac82701dc3f1dd95732848/mappings/v2game-3.04.toml),
[console capture](https://github.com/adrunkhuman/smedley_kernel/blob/a87832e6196168b6b6ac82701dc3f1dd95732848/kernel/src/events/console.cpp),
[narrow call records](https://github.com/adrunkhuman/smedley_kernel/blob/a87832e6196168b6b6ac82701dc3f1dd95732848/kernel/game_state/src/console_layout.hpp),
[checked invocation](https://github.com/adrunkhuman/smedley_kernel/blob/a87832e6196168b6b6ac82701dc3f1dd95732848/kernel/game_state/src/runtime.cpp)
and [observer evidence](https://github.com/adrunkhuman/smedley_kernel/blob/a87832e6196168b6b6ac82701dc3f1dd95732848/mappings/evidence/campaign-automation.md#observer-ownership-and-view).

Historical runtime evidence lacks exact-built-commit provenance. It supports
the exercised debug/FOW and asynchronous-tag boundaries, not acceptance of
later builds. Descriptor/result layouts are current implementation evidence
with the selective static corroboration above; arbitrary handler behavior,
manager lifetime across transitions, registration ownership and allocation
compatibility still require dedicated native caller review. No generic command
mutation, installation, worker-thread invocation or plugin ABI is exported.
