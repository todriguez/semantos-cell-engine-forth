\ linearity.fs — Substructural type enforcement for semantic cells
\ Zig source: semantos-core/core/cell-engine/src/linearity.zig
\
\ Three linearity classes enforce resource semantics at the stack level:
\
\   LINEAR   (1) — must be consumed exactly once.  No DUP, no DROP.
\                  This is money: spend it exactly once.
\
\   AFFINE   (2) — may be consumed at most once.  No DUP; DROP allowed.
\                  A session key: use it or discard it.
\
\   RELEVANT (3) — must be consumed at least once.  DUP allowed; no DROP.
\                  A public key: copy freely, cannot be destroyed.
\
\   DEBUG    (4) — unrestricted.  Development scaffolding only.
\
\ Five operation classes:
\   duplicate  — OP_DUP, OP_OVER, OP_PICK, SCELL-DUP
\   discard    — OP_DROP, OP_2DROP, SDROP
\   consume    — OP_CHECKSIG and other read-and-use ops
\   swap       — OP_SWAP, OP_ROT (reorder, no copy/destroy)
\   inspect    — SPEEK, .STACK-TOP (read-only, no side effects)
\
\ Enforcement is opt-in so test vectors can run with DEBUG cells.
\ Call LINEARITY-STRICT to enable; LINEARITY-RELAX to disable.
\ The executor calls LINEARITY-CHECK-DUP / LINEARITY-CHECK-DISCARD before
\ each matching opcode.

[DEFINED] SCELL-LINEARITY-LOADED [IF] EXIT [THEN]
TRUE CONSTANT SCELL-LINEARITY-LOADED

REQUIRE constants.fs
REQUIRE cell.fs

\ ── Enforcement toggle ────────────────────────────────────────────────────────

VARIABLE LINEARITY-STRICT-MODE
TRUE LINEARITY-STRICT-MODE !   \ on by default

: LINEARITY-STRICT ( -- )  TRUE  LINEARITY-STRICT-MODE ! ;
: LINEARITY-RELAX  ( -- )  FALSE LINEARITY-STRICT-MODE ! ;

\ ── Core check words ──────────────────────────────────────────────────────────
\ These are the words the executor calls.  Each takes the linearity u32 from
\ the cell header — not the cell address — so the check is zero-copy.

: LINEARITY-CHECK-DUP ( linearity -- )
  \ Reject if the cell cannot be duplicated.
  LINEARITY-STRICT-MODE @ 0= IF DROP EXIT THEN
  DUP LINEARITY-LINEAR   = IF DROP CR ." LINEARITY: cannot duplicate LINEAR cell"   CR ABORT THEN
  DUP LINEARITY-AFFINE   = IF DROP CR ." LINEARITY: cannot duplicate AFFINE cell"   CR ABORT THEN
  DROP ;   \ RELEVANT and DEBUG: DUP is fine

: LINEARITY-CHECK-DISCARD ( linearity -- )
  \ Reject if the cell cannot be discarded (dropped without consuming).
  LINEARITY-STRICT-MODE @ 0= IF DROP EXIT THEN
  DUP LINEARITY-LINEAR   = IF DROP CR ." LINEARITY: cannot discard LINEAR cell"   CR ABORT THEN
  DUP LINEARITY-RELEVANT = IF DROP CR ." LINEARITY: cannot discard RELEVANT cell" CR ABORT THEN
  DROP ;   \ AFFINE and DEBUG: DROP is fine

\ ── Convenience wrappers that take a cell address ─────────────────────────────

: CELL-CHECK-DUP     ( addr -- )  CELL-LINEARITY@ LINEARITY-CHECK-DUP     ;
: CELL-CHECK-DISCARD ( addr -- )  CELL-LINEARITY@ LINEARITY-CHECK-DISCARD ;

\ ── Linearity-aware stack operations ─────────────────────────────────────────

: SCELL-DUP ( -- )
  \ Duplicate top of main stack — enforces linearity.
  SPEEK
  DUP CELL-CHECK-DUP
  SPUSH ;

: SCELL-DROP ( -- )
  \ Discard top of main stack — enforces linearity.
  SPEEK CELL-CHECK-DISCARD
  SPOP DROP ;

: SCELL-OVER ( -- )
  \ Copy 2nd-from-top to top — enforces linearity on the source cell.
  1 SPICK
  DUP CELL-CHECK-DUP
  SPUSH ;

\ ── Domain flag tier classifier ───────────────────────────────────────────────

255   CONSTANT FLAG-TIER-WELL-KNOWN-MAX   \ 0x00FF
65535 CONSTANT FLAG-TIER-EXTENDED-MAX    \ 0xFFFF

: FLAG-TIER ( flag -- tier )
  \ 0=reserved  1=well-known [1..255]  2=extended [256..65535]  3=sovereign
  DUP 0= IF DROP 0 EXIT THEN
  DUP FLAG-TIER-WELL-KNOWN-MAX <= IF DROP 1 EXIT THEN
  DUP FLAG-TIER-EXTENDED-MAX   <= IF DROP 2 EXIT THEN
  DROP 3 ;

: .FLAG-TIER ( flag -- )
  FLAG-TIER
  CASE
    0 OF ." reserved"   ENDOF
    1 OF ." well-known" ENDOF
    2 OF ." extended"   ENDOF
    3 OF ." sovereign"  ENDOF
    ." (unknown)"
  ENDCASE ;

\ ── Diagnostic ───────────────────────────────────────────────────────────────

: .LINEARITY-STATUS ( -- )
  CR
  LINEARITY-STRICT-MODE @ IF
    ." Linearity enforcement: STRICT"
  ELSE
    ." Linearity enforcement: RELAXED (debug mode)"
  THEN CR ;
