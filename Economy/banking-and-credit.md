# Banking and credit

Loan principal, bank reserves, pending interest, state interest pools and POP
cash-flow accounting are distinct balances. Loan origination and ordinary
repayment do not transfer bank reserves to or from the debtor.

Addresses are preferred x86 **VAs** (image base `0x00400000`); offsets are relative
to complete objects. Static claims describe reviewed instructions. Runtime
correlations cover selected fields and paths, not entire layouts or every branch.

## Fields and units

| Object | Offset | Meaning |
| --- | --- | --- |
| `CCountry` | `+0xE78/+0xE7C` | Int64 treasury |
| `CCountry` | `+0xE88` | Bank pointer |
| `CCountry` | `+0xE8C/+0xE90` | Creditor-vector begin/end |
| `CBank` | `+0x08` | Owner-country pointer |
| `CBank` | `+0x10` | Int64 reserves (`money`) |
| `CBank` | `+0x18` | Int64 lent principal (`money_lent`) |
| `CBank` | `+0x20` | Int64 pending interest (`interest_payments`) |
| `CCreditor` | `+0x08/+0x0C` | Destination tag/ordinal |
| `CCreditor` | `+0x10` | Int64 interest rate |
| `CCreditor` | `+0x18` | Int64 principal |
| `CCreditor` | `+0x20` | Paid byte |
| `CState` | `+0x258` | Int64 savings |
| `CState` | `+0x260` | Int64 accumulated interest |
| `CPop` | `+0x250` | Int64 savings at 1,000 times state scale |

Treasury, bank, creditor and state values use signed 48.15 fixed point:
`value = raw / 32768`. POP savings and payment amounts use `/32768000`.
The fields above have narrow runtime correlations. `CCountry+0xE80` remains
unidentified. Displayed national-bank balances are not established as direct
presentations of bank `money` and `money_lent`.

## Function boundaries

Names describe roles, not recovered source-level symbols.

| VA | Role | Evidence |
| --- | --- | --- |
| `0x00522910` | `CCountry::TakeLoan` | Static callsites |
| `0x00523400` | Create/increase creditor debt and credit loan proceeds; also handles rates | Static stores; named principal flows runtime-correlated |
| `0x005238D0` | `CCountry::RepayLoan` | Static body and runtime principal flows |
| `0x00523C30` | `CCountry::PayDailyInterest` | Static body and sufficient-payment runtime correlations |
| `0x004F5BF0` | `CBank::DistributeInterest` | Static body and ordinary-allocation runtime correlations |
| `0x0095A5F0` | `CPop::GiveMoney` | Static ABI and narrow runtime field effects |

`0x00523400` is **not just an interest calculator**. Its named-lender path
increases principal, treasury and bank lent principal at
`0x0052367F`–`0x005236A2`.

## Origination and repayment

`TakeLoan` attempts a domestic self-tagged creditor before the ordinal-zero
fallback. The domestic call loads the debtor's tag/ordinal at
`0x00522941/0x00522944`; it is not Private Investor borrowing. The fallback
passes tag `---` (`0x2D2D2D`) and ordinal zero at
`0x00522C27/0x00522C28`. Localisation displays it as “Private Investors”.

For successful named borrowing and sufficient-treasury named repayment:

| Operation | Debtor treasury | Creditor principal | Lender-bank lent | Bank reserves |
| --- | --- | --- | --- | --- |
| Origination | Increases | Increases | Increases | Unchanged |
| Ordinary repayment | Decreases | Decreases | Decreases, clamped at zero | Unchanged |

The corresponding treasury and principal changes agree exactly on these paths.
Repayment removes fully repaid entries at `0x00523AF0`–`0x00523B87`.
This is not a reserve-transfer model or a contract for insufficient funds.

Ordinal zero has different rules at different stages:

| Path | Static contract |
| --- | --- |
| Existing creditor top-up | `0x00523561`–`0x005235BB` increases principal/treasury without a bank-lent store. |
| New creditor | `0x0052348E`–`0x0052349A` resolves the bank, including country slot zero. `0x00523806`–`0x00523834` tests bank-pointer nullness, not ordinal, before increasing lent principal. |
| Interest | Skips destination-bank pending credit. |
| Repayment | Skips lender-bank lent reduction at `0x0052397C/0x00523980`. |

Slot zero can have a non-null bank. Its lent field is not a mirror of all
outstanding ordinal-zero principal. Interest and repayment skips do not imply
that origination never mutates that bank.

## Borrower to bank

Country daily update calls `PayDailyInterest` at `0x00508D3E`. The routine
multiplies principal by rate, clears the low 15 product bits and divides by
`0x000F0000` (30 in 48.15) at `0x00523F45`–`0x00523F68`. Foreign-only rate
adjustment is skipped when creditor ordinal equals debtor ordinal.

With sufficient funds, it debits treasury, credits the resolved nonzero-ordinal
bank's pending interest at `0x00524170`–`0x00524199`, and sets the creditor paid
byte. Treasury debit and bank pending credit agree exactly on the observed
sufficient named-payment path. Ordinal zero skips bank credit at
`0x00524170/0x00524174` and `0x00524022/0x00524026`.

Insufficient interest is a separate path: it accumulates a shortfall and leaves
the paid byte clear. Shortfall handling can cancel construction and conditionally
refund treasury (`0x005246EB`–`0x00524701`). Net treasury movement therefore does
not identify the amount delivered to a bank on every branch.

The shortfall handler `0x005241F0` does not directly establish principal write-off.
`RemoveDebts` (`0x00511340`) is a separate operation, called directly at
`0x00508ACE` and `0x00518EE6`. Unlike ordinary repayment, its reviewed body can
reduce both bank lent principal and reserves. Automatic-default timing and
complete downstream accounting remain unresolved.

## Bank to state

The post-country loop calls `DistributeInterest` at `0x00685F0F`, passing each
country's `+0xE88` bank. The routine:

1. Adds positive pending interest to reserves if reserves are at most **33 raw
   units**, not £33. The double `33.268` at `0x00E45900` is converted to integer
   without fixed-point scaling.
2. Otherwise walks the owner's state list and weights the **original** pending
   amount by each state's savings, using bank reserves as denominator. It clears
   the low 15 product bits, then performs signed division (truncation toward zero).
3. Adds shares to state `+0x260` at `0x004F5CA4/0x004F5CAE` or
   `0x004F5CBE/0x004F5CC8`, and clears bank pending interest on every return path.
   Nonpositive pending interest is also cleared.

Ordinary shares reduce a local remainder. An oversized share is clamped to that
remainder, but its branch does **not** reset the remainder before continuing
(`0x004F5CA0`–`0x004F5CB4`). A positive final remainder is discarded.

**Bank-to-state allocation is not generally conservative.** Rounding and state
weights that do not sum to reserves can lose interest; the oversized-share branch
can potentially over-allocate. Ordinary allocation and clearing are
runtime-correlated. Low-reserve recapitalization and over-allocation are static
findings, not exercised runtime outcomes. Why state weights differ from reserves
remains unresolved.

## State to POP: no identified consumer

Save parsing/formatting names state `+0x258` as `savings` and `+0x260` as
`interest`. Reviewed references cover construction, copying, parsing, formatting
and bank allocation, but no gameplay subtraction, clear or POP payout consumer.
Observed state pools accumulate without corresponding POP index-7 payments.
This does **not** exclude later, indirect, aliased, inlined or transient payouts.

POP savings are at 1,000 times state scale; conversion uses raw `32768000` at
`0x00F0B168`. Summing individually truncated POP savings is not an exact substitute
for stored state savings. This scale conversion does not repair bank-allocation
loss.

`GiveMoney` uses EAX=POP, ESI=flow index, one stack int64 amount and `ret 8`.
It updates money `+0x180`, indexed flow `+0x1D8 + 8*index` and total flow `+0x218`,
not savings `+0x250`. Index 7 is interest at `+0x210`; presentation at
`0x00966440` uses `POP_DAILY_INTEREST`. All 15 reviewed direct callers select
indices 0–6, none 7; indirect or inlined mutations remain outside that scan.
Money clamps can make the actual money delta differ from the posted flow amount.

These balances are not interchangeable parts of a money-supply identity.
The findings do not establish safe arbitrary mutation, save compatibility,
multiplayer behavior or an intended economic policy.

Native allocation extents are separate from these economic contracts;
see [object storage](object-storage.md).
