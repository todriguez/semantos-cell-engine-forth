\ tests/run-m1.fs — M1 milestone: cell, 2-PDA, linearity
REQUIRE ../bootstrap.fs

VARIABLE TEST-PASS  0 TEST-PASS !
VARIABLE TEST-FAIL  0 TEST-FAIL !

: PASS ( -- )  1 TEST-PASS +!  ." PASS" CR ;
: FAIL ( -- )  1 TEST-FAIL +!  ." FAIL" CR ;
: ASSERT-TRUE  ( flag -- )  IF PASS ELSE FAIL THEN ;
: ASSERT-FALSE ( flag -- )  0= ASSERT-TRUE ;

: BUILD-CELL ( linearity -- )
  SCELL-ALLOC DUP CELL-DEFAULT SWAP OVER CELL-LINEARITY! SCELL-PUSH ;

\ ── T01: cell construction + header fields ───────────────────────────────────

: T01 ( -- )
  ." T01: cell build + header fields" CR
  SCELL-ALLOC DUP CELL-DEFAULT
  DUP CELL-MAGIC-VALID?              ASSERT-TRUE
  DUP CELL-VERSION@    2 =           ASSERT-TRUE
  DUP CELL-REF-COUNT@  1 =           ASSERT-TRUE
  DUP CELL-LINEARITY@  LINEARITY-DEBUG = ASSERT-TRUE
  DROP ;

\ ── T02: write linearity field ───────────────────────────────────────────────

: T02 ( -- )
  ." T02: write linearity field" CR
  SCELL-ALLOC DUP CELL-DEFAULT
  DUP LINEARITY-LINEAR SWAP CELL-LINEARITY!
  CELL-LINEARITY@ LINEARITY-LINEAR = ASSERT-TRUE ;

\ ── T03: 2-PDA push / peek / pop ─────────────────────────────────────────────

: T03 ( -- )
  ." T03: 2-PDA push / peek / pop" CR
  LINEARITY-LINEAR BUILD-CELL
  S-DEPTH 1 =                        ASSERT-TRUE
  SCELL-PEEK CELL-MAGIC-VALID?       ASSERT-TRUE
  SCELL-PEEK CELL-LINEARITY@ LINEARITY-LINEAR = ASSERT-TRUE
  SCELL-POP DROP
  S-DEPTH 0 =                        ASSERT-TRUE ;

\ ── T04: OP_TOALTSTACK / OP_FROMALTSTACK ─────────────────────────────────────

: T04 ( -- )
  ." T04: OP_TOALTSTACK / OP_FROMALTSTACK" CR
  LINEARITY-AFFINE BUILD-CELL
  S-DEPTH 1 = A-DEPTH 0 = AND        ASSERT-TRUE
  OP-TOALTSTACK
  S-DEPTH 0 = A-DEPTH 1 = AND        ASSERT-TRUE
  OP-FROMALTSTACK
  S-DEPTH 1 = A-DEPTH 0 = AND        ASSERT-TRUE
  RESET-STACKS ;

\ ── T05: DUP on LINEAR must abort ────────────────────────────────────────────

: T05 ( -- )
  ." T05: SCELL-DUP on LINEAR aborts" CR
  LINEARITY-LINEAR BUILD-CELL
  ['] SCELL-DUP CATCH 0<> ASSERT-TRUE
  RESET-STACKS ;

\ ── T06: DUP on RELEVANT must succeed ────────────────────────────────────────

: T06 ( -- )
  ." T06: SCELL-DUP on RELEVANT succeeds" CR
  LINEARITY-RELEVANT BUILD-CELL
  ['] SCELL-DUP CATCH 0= ASSERT-TRUE
  RESET-STACKS ;

\ ── T07: DROP on RELEVANT must abort ─────────────────────────────────────────

: T07 ( -- )
  ." T07: SCELL-DROP on RELEVANT aborts" CR
  LINEARITY-RELEVANT BUILD-CELL
  ['] SCELL-DROP CATCH 0<> ASSERT-TRUE
  RESET-STACKS ;

\ ── T08: DROP on AFFINE must succeed ─────────────────────────────────────────

: T08 ( -- )
  ." T08: SCELL-DROP on AFFINE succeeds" CR
  LINEARITY-AFFINE BUILD-CELL
  ['] SCELL-DROP CATCH 0= ASSERT-TRUE
  RESET-STACKS ;

\ ── T09: LE32 read/write round-trip ──────────────────────────────────────────

: T09 ( -- )
  ." T09: LE32 read/write round-trip" CR
  SCELL-ALLOC DUP CELL-ZERO   \ addr
  $DEADBEEF OVER LE32!        \ write 0xDEADBEEF at addr; stack: addr
  LE32@  $DEADBEEF =          \ read back; stack: flag
  ASSERT-TRUE ;

\ ── T10: LE64 read/write round-trip ──────────────────────────────────────────

: T10 ( -- )
  ." T10: LE64 read/write round-trip" CR
  SCELL-ALLOC DUP CELL-ZERO   \ addr
  $123456789ABCDEF OVER LE64! \ write 64-bit value; stack: addr
  LE64@  $123456789ABCDEF =   \ read back; stack: flag
  ASSERT-TRUE ;

\ ── Run all ───────────────────────────────────────────────────────────────────

T01 T02 T03 T04 T05 T06 T07 T08 T09 T10

CR .( ── M1 results ──────────────────────────────────────────) CR
.( PASS: ) TEST-PASS @ . CR
.( FAIL: ) TEST-FAIL @ . CR
: .M1-SUMMARY ( -- )
  TEST-FAIL @ 0= IF ." All M1 tests passed." CR
               ELSE ." Some M1 tests FAILED." CR THEN ;
.M1-SUMMARY
