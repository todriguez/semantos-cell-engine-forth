\ bootstrap.fs — Semantos cell-engine in Forth
\ Load order: constants → cell → 2pda → linearity → type-hash → sighash → executor → opcodes
\
\ Usage:  gforth bootstrap.fs
\
\ After loading:
\   SCELL-ALLOC    allocate a staging cell
\   CELL-DEFAULT   zero + set magic/version/ref-count
\   SCELL-PUSH     push cell onto main 2-PDA stack
\   SCELL-POP      pop top cell (returns byte address)
\   CELL-DUMP      pretty-print header fields
\   .LINEARITY-STATUS   show enforcement mode
\   VERIFY-TYPE-HASH-PARITY   run cross-runtime parity check

REQUIRE core/constants.fs
REQUIRE core/cell.fs
REQUIRE core/2pda.fs
REQUIRE core/linearity.fs
REQUIRE core/type-hash.fs
REQUIRE core/sighash.fs

REQUIRE core/executor.fs
REQUIRE opcodes/standard.fs

\ Future modules — guarded until files exist:
[DEFINED] SCELL-MACRO-OPS         [IF] REQUIRE opcodes/macro.fs      [THEN]
[DEFINED] SCELL-ROUTING-OPS       [IF] REQUIRE opcodes/routing.fs    [THEN]
[DEFINED] SCELL-HOSTCALL-OPS      [IF] REQUIRE opcodes/hostcall.fs   [THEN]
[DEFINED] SCELL-MNCA-TILE-LOADED  [IF] REQUIRE mnca/tile.fs          [THEN]

: .BOOT-BANNER ( -- )
  CR ." ── Semantos cell-engine (Forth) loaded ──────────────────" CR
  ." Protocol:  " SCELL-SIZE . ." B cells, " HEADER-SIZE . ." B header" CR
  ." Stacks:    " MAIN-STACK-CELLS . ." main × " SCELL-SIZE . ." B  |  "
                 AUX-STACK-CELLS  . ." aux"  CR
  .LINEARITY-STATUS
  CR ;
.BOOT-BANNER
