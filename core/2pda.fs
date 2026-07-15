\ 2pda.fs — Two-stack pushdown automaton for 1KB semantic cells
\ Curated from semantos-gift-pack/forth/bitcoin-2pda.fs.
\
\ Bitcoin Script is a 2-PDA: main stack + alt stack, each operating on
\ 1024-byte semantic cells.  This maps exactly to OP_TOALTSTACK /
\ OP_FROMALTSTACK.  Single scripts are DFA-bounded; Turing completeness
\ emerges through transaction chaining.
\
\ Stack words follow the convention:
\   SPUSH / SPOP   — main stack, full 1KB cell copy
\   APUSH / APOP   — alt (auxiliary) stack
\   SPEEK / APEEK  — top cell address without popping
\   SPICK          — nth cell address from top (0=top)
\   SDROP / ADROP  — discard top (linearity-checked by linearity.fs)
\
\ All stacks live in static memory allocated at load time.
\ Never use ALLOT inside a word definition.

[DEFINED] SCELL-2PDA-LOADED [IF] EXIT [THEN]
TRUE CONSTANT SCELL-2PDA-LOADED

REQUIRE constants.fs

\ ── Static stack memory ───────────────────────────────────────────────────────

CREATE MAIN-STACK-MEM  MAIN-STACK-CELLS SCELL-SIZE * ALLOT
CREATE AUX-STACK-MEM   AUX-STACK-CELLS  SCELL-SIZE * ALLOT

MAIN-STACK-MEM CONSTANT MAIN-STACK-BASE
MAIN-STACK-MEM MAIN-STACK-CELLS SCELL-SIZE * + CONSTANT MAIN-STACK-LIMIT
AUX-STACK-MEM  CONSTANT AUX-STACK-BASE
AUX-STACK-MEM  AUX-STACK-CELLS  SCELL-SIZE * + CONSTANT AUX-STACK-LIMIT

\ Stack pointers — point to the next *free* slot (one past the top).
VARIABLE SP  \ main stack pointer
VARIABLE AP  \ aux stack pointer

: RESET-STACKS ( -- )
  MAIN-STACK-BASE SP !
  AUX-STACK-BASE  AP ! ;

RESET-STACKS

\ ── Depth ─────────────────────────────────────────────────────────────────────

: S-DEPTH ( -- n )  SP @ MAIN-STACK-BASE -  SCELL-SIZE / ;
: A-DEPTH ( -- n )  AP @ AUX-STACK-BASE  -  SCELL-SIZE / ;
: S-EMPTY? ( -- f )  S-DEPTH 0= ;
: A-EMPTY? ( -- f )  A-DEPTH 0= ;

\ ── Main stack ────────────────────────────────────────────────────────────────

: SPUSH ( src-addr -- )
  \ Copy 1024 bytes from src-addr into the next main-stack slot.
  SP @ MAIN-STACK-LIMIT >= IF
    CR ." SPUSH: main stack overflow" CR ABORT
  THEN
  SP @  SCELL-SIZE MOVE     \ MOVE( src dst n ): src-addr → SP-slot
  SCELL-SIZE SP +! ;        \ advance pointer

: SPOP ( -- addr )
  \ Retreat pointer and return address of the now-free-but-still-valid slot.
  S-EMPTY? IF
    CR ." SPOP: main stack underflow" CR ABORT
  THEN
  SCELL-SIZE NEGATE SP +!
  SP @ ;

: SPEEK ( -- addr )
  S-EMPTY? IF
    CR ." SPEEK: main stack empty" CR ABORT
  THEN
  SP @ SCELL-SIZE - ;

: SPICK ( n -- addr )
  \ Address of the nth cell from the top (0 = top).
  DUP S-DEPTH >= IF
    DROP CR ." SPICK: index out of range" CR ABORT
  THEN
  1+ SCELL-SIZE *  NEGATE  SP @ + ;

: SDROP ( -- )
  \ Discard top cell — linearity.fs wraps this to reject LINEAR/RELEVANT.
  SPOP DROP ;

\ ── Alt stack ─────────────────────────────────────────────────────────────────

: APUSH ( src-addr -- )
  AP @ AUX-STACK-LIMIT >= IF
    CR ." APUSH: alt stack overflow" CR ABORT
  THEN
  AP @  SCELL-SIZE MOVE     \ MOVE( src dst n ): src-addr → AP-slot
  SCELL-SIZE AP +! ;

: APOP ( -- addr )
  A-EMPTY? IF
    CR ." APOP: alt stack underflow" CR ABORT
  THEN
  SCELL-SIZE NEGATE AP +!
  AP @ ;

: APEEK ( -- addr )
  A-EMPTY? IF
    CR ." APEEK: alt stack empty" CR ABORT
  THEN
  AP @ SCELL-SIZE - ;

: ADROP ( -- )
  APOP DROP ;

\ ── Convenience: push from cell address ───────────────────────────────────────
\ These copy the full 1KB cell into the appropriate stack storage.

: SCELL-PUSH  ( addr -- )  SPUSH ;     \ push cell to main stack
: SCELL-APUSH ( addr -- )  APUSH ;     \ push cell to alt stack
: SCELL-POP   ( -- addr )  SPOP  ;     \ pop from main (addr valid until next SPUSH)
: SCELL-APOP  ( -- addr )  APOP  ;     \ pop from alt
: SCELL-PEEK  ( -- addr )  SPEEK ;     \ peek main stack top

\ ── OP_TOALTSTACK / OP_FROMALTSTACK ─────────────────────────────────────────

: OP-TOALTSTACK ( -- )
  \ Move top of main stack to alt stack without re-checking linearity.
  SPOP APUSH ;

: OP-FROMALTSTACK ( -- )
  \ Move top of alt stack back to main stack.
  APOP SPUSH ;

\ ── Display ───────────────────────────────────────────────────────────────────

: .STACK-SUMMARY ( -- )
  CR
  ." Main stack: " S-DEPTH . ." cells" CR
  ." Alt  stack: " A-DEPTH . ." cells" CR ;

: .STACK-TOP ( -- )
  S-EMPTY? IF
    CR ." (main stack empty)" CR
  ELSE
    CR ." Top cell:" SPEEK CELL-DUMP
  THEN ;
