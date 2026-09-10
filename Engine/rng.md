# PART III — RANDOM NUMBER GENERATOR (RNG) SYSTEM

```text
                         v2game.exe+0xb0ecf0
                       RANDOM NUMBER LIST
                                  │
                                  ▼
                         v2game.exe+0xb0f6b0
                        CURRENT LIST INDEX
                                  │
                                  ▼
                          fun_009b7610
                    FUNCTION THAT POLLS A NUMBER
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
                    ▼                           ▼
             INDEX + 1                   LIST EXHAUSTED?
                    │                           │
                    ▼                           ▼
          RETURNS NUMBER                 fun_009b7700
                                          │
                                          ▼
                                  GENERATES NEW LIST
                                  USING MERSENNE TWISTER
```

The list state uses:

```text
v2game.exe+0xb0ecf0
```

Current index:

```text
v2game.exe+0xb0f6b0
```

`fun_009b7610` polls the next number.

When exhausted, `fun_009b7700` regenerates the list.

The regeneration uses the Mersenne Twister / MT19937 family.
