# Catalog

`summary.json` contains aggregate metadata only: coverage, entry kinds,
size distribution and lift counters.

A full function catalog (`address`, `size`, `entry_kind`, `blocks`,
`instructions`, `thunk`) can be generated locally from the pcrecomp
`functions.json`. It is not included in this baseline PR to keep the review
focused and to avoid publishing a large, derived artifact before the metadata
schema is agreed.
