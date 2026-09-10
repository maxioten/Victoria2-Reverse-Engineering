# PART V — ARTISAN / FACTORY STOCKPILE SUBTRACTION

## MAP 13 — `SubtractArtisanFactoryStockpileFromESIStockpile` — 0x0047DCA0

This function provides important evidence about how goods and stockpiles are represented.

```text
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│         SubtractArtisanFactoryStockpileFromESIStockpile  (0x0047dca0)                        │
└──────────────────────────────────────────────────────────────────────────────────────────────┘

For each good:

artisan/factory.good_bit_flags[idx]
                │
                ▼
          Is good present?
                │
          ┌─────┴─────┐
          │           │
         NO          YES
          │           │
          ▼           ▼
        SKIP    Check destination ESI
                         │
                  ┌──────┴──────┐
                  │             │
              absent          present
                  │             │
                  ▼             ▼
           create entry    subtract int64
           with -amount    directly
```

Important fields:

```text
[0x12587f4]
    number_of_goods

[entity + 0x08 + idx]
    good bitflag / positional index

[entity + 0x48]
    stockpile vector begin

[entity + 0x4C]
    stockpile vector end
```

Stockpile entries are:

```text
8 bytes
=
64-bit integer
=
2 × int32
```

The vector size is obtained through:

```text
(end - begin) >> 3
```

When the destination has no entry:

```text
artisan/factory amount
        ↓
NEG 64-bit value
        ↓
push_back into ESI stockpile vector
```

When the destination already has an entry:

```text
ESI stockpile
        -
artisan/factory stockpile
        ↓
64-bit SUB + SBB
```

Therefore the conceptual result is:

```text
ESI.stockpile[good]
    -=
artisan/factory.stockpile[good]
```

### Important finding

The byte at:

```text
entity + 0x08 + good_index
```

acts as a presence/index structure.

The actual amount is stored in the stockpile vector at:

```text
entity + 0x48
```

with 8-byte entries.

This is important for understanding the goods representation used by the market system.
