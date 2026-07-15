\ cell.fs — 1024-byte semantic cell accessors
\ Zig source: semantos-core/core/cell-engine/src/cell.zig
\
\ Wire format is byte-identical to the TypeScript packCell/unpackCell and the
\ Zig implementation.  All multi-byte integers are little-endian.
\
\ Design: accessors work directly on byte addresses — no separate handle type.
\ Callers hold addresses into stack buffers or the staging pool.  Build a cell
\ in the staging pool, fill its fields, then push it onto the 2-PDA with
\ SCELL-PUSH.

[DEFINED] SCELL-CELL-LOADED [IF] EXIT [THEN]
TRUE CONSTANT SCELL-CELL-LOADED

REQUIRE constants.fs

\ ── Portable little-endian read/write ─────────────────────────────────────────
\ gforth @ is native-endian; we need wire-LE regardless of host.

: LE16! ( u16 addr -- )
  \ Write u16 little-endian at addr.  Consumes both args; no DROP needed.
  2DUP        C!              \ store low byte (copy of addr on stack)
  1+  SWAP  8 RSHIFT  SWAP C! ;  \ store high byte at addr+1

: LE16@ ( addr -- u16 )
  DUP C@                      \ low byte
  SWAP 1+ C@  8 LSHIFT  OR ;  \ | (high byte << 8)

: LE32! ( u32 addr -- )
  2DUP        LE16!           \ write low 16 bits
  SWAP  16 RSHIFT  SWAP  2 +  LE16! ;  \ write high 16 bits at addr+2

: LE32@ ( addr -- u32 )
  DUP  LE16@
  SWAP  2 +  LE16@  16 LSHIFT  OR ;

: LE64! ( u64 addr -- )
  2DUP        LE32!           \ write low 32 bits
  SWAP  32 RSHIFT  SWAP  4 +  LE32! ;  \ write high 32 bits at addr+4

: LE64@ ( addr -- u64 )
  DUP  LE32@
  SWAP  4 +  LE32@  32 LSHIFT  OR ;

\ ── Staging pool ──────────────────────────────────────────────────────────────
\ A small pool of pre-allocated 1KB slots for building cells before pushing
\ them onto the 2-PDA.  The 2-PDA stacks hold their own copies once pushed.

32 CONSTANT STAGING-SLOTS
CREATE SCELL-STAGING  STAGING-SLOTS SCELL-SIZE * ALLOT
VARIABLE SCELL-STAGING-PTR  0 SCELL-STAGING-PTR !

: SCELL-ALLOC ( -- addr )
  SCELL-STAGING-PTR @ STAGING-SLOTS >= IF
    CR ." SCELL-ALLOC: staging pool exhausted" CR ABORT
  THEN
  SCELL-STAGING-PTR @  SCELL-SIZE *  SCELL-STAGING +
  1 SCELL-STAGING-PTR +! ;

: SCELL-STAGING-RESET ( -- )
  0 SCELL-STAGING-PTR ! ;

\ ── Cell initialisation ───────────────────────────────────────────────────────

: CELL-ZERO ( addr -- )
  SCELL-SIZE 0 FILL ;

: CELL-SET-MAGIC ( addr -- )
  SCELL-MAGIC SWAP  16 MOVE ;

: CELL-MAGIC-VALID? ( addr -- flag )
  \ COMPARE ( a1 u1 a2 u2 -- n ): compare 16 bytes at addr vs SCELL-MAGIC.
  16  SCELL-MAGIC 16  COMPARE 0= ;

: CELL-DEFAULT ( addr -- )
  \ Zero cell, set magic, version=2, ref_count=1, linearity=DEBUG (unchecked).
  DUP  CELL-ZERO
  DUP  CELL-SET-MAGIC
  DUP  OFF-VERSION  +  SCELL-VERSION  SWAP LE32!
  DUP  OFF-REF-COUNT + 1               SWAP LE16!
       OFF-LINEARITY + LINEARITY-DEBUG SWAP LE32! ;

\ ── Header field readers ──────────────────────────────────────────────────────

: CELL-LINEARITY@    ( addr -- u32 )  OFF-LINEARITY    + LE32@ ;
: CELL-VERSION@      ( addr -- u32 )  OFF-VERSION      + LE32@ ;
: CELL-FLAGS@        ( addr -- u32 )  OFF-FLAGS        + LE32@ ;
: CELL-REF-COUNT@    ( addr -- u16 )  OFF-REF-COUNT    + LE16@ ;
: CELL-TIMESTAMP@    ( addr -- u64 )  OFF-TIMESTAMP    + LE64@ ;
: CELL-CELL-COUNT@   ( addr -- u32 )  OFF-CELL-COUNT   + LE32@ ;
: CELL-PAYLOAD-LEN@  ( addr -- u32 )  OFF-PAYLOAD-TOTAL + LE32@ ;

\ Return address of fixed-size byte fields (caller reads N bytes from there).
: CELL-TYPE-HASH-ADDR   ( addr -- addr )  OFF-TYPE-HASH       + ;
: CELL-OWNER-ID-ADDR    ( addr -- addr )  OFF-OWNER-ID        + ;
: CELL-PARENT-HASH-ADDR ( addr -- addr )  OFF-PARENT-HASH     + ;
: CELL-PREV-STATE-ADDR  ( addr -- addr )  OFF-PREV-STATE-HASH + ;
: CELL-DOMAIN-ROOT-ADDR ( addr -- addr )  OFF-DOMAIN-ROOT     + ;
: CELL-PAYLOAD-ADDR     ( addr -- addr )  OFF-PAYLOAD         + ;

\ ── Header field writers ──────────────────────────────────────────────────────

: CELL-LINEARITY!    ( u32 addr -- )  OFF-LINEARITY     + LE32! ;
: CELL-VERSION!      ( u32 addr -- )  OFF-VERSION       + LE32! ;
: CELL-FLAGS!        ( u32 addr -- )  OFF-FLAGS         + LE32! ;
: CELL-REF-COUNT!    ( u16 addr -- )  OFF-REF-COUNT     + LE16! ;
: CELL-TIMESTAMP!    ( u64 addr -- )  OFF-TIMESTAMP     + LE64! ;
: CELL-CELL-COUNT!   ( u32 addr -- )  OFF-CELL-COUNT    + LE32! ;
: CELL-PAYLOAD-LEN!  ( u32 addr -- )  OFF-PAYLOAD-TOTAL + LE32! ;

: CELL-TYPE-HASH!    ( src-addr addr -- )  OFF-TYPE-HASH       +  32 MOVE ;
: CELL-OWNER-ID!     ( src-addr addr -- )  OFF-OWNER-ID        +  16 MOVE ;
: CELL-PARENT-HASH!  ( src-addr addr -- )  OFF-PARENT-HASH     +  32 MOVE ;
: CELL-PREV-STATE!   ( src-addr addr -- )  OFF-PREV-STATE-HASH +  32 MOVE ;
: CELL-DOMAIN-ROOT!  ( src-addr addr -- )  OFF-DOMAIN-ROOT     +  32 MOVE ;

\ Write up to PAYLOAD-SIZE bytes of payload and update payload-total field.
: CELL-PAYLOAD! ( src-addr len cell-addr -- )
  DUP >R                                  \ save cell-addr
  R@ CELL-PAYLOAD-ADDR  SWAP MOVE         \ copy payload bytes
  R>  CELL-PAYLOAD-LEN! ;                 \ write len into header

\ ── Validate ──────────────────────────────────────────────────────────────────

: CELL-VALID? ( addr -- flag )
  \ Basic sanity: magic correct and payload-total <= PAYLOAD-SIZE.
  DUP CELL-MAGIC-VALID? IF
    CELL-PAYLOAD-LEN@ PAYLOAD-SIZE <=
  ELSE
    DROP FALSE
  THEN ;

\ ── Display (debugging / REPL inspection) ─────────────────────────────────────

: .HEX-BYTES ( addr n -- )
  0 ?DO
    DUP I + C@
    DUP 16 < IF ." 0" THEN
    HEX . DECIMAL
  LOOP DROP ;

: .LINEARITY ( u32 -- )
  DUP LINEARITY-LINEAR   = IF DROP ." LINEAR"   EXIT THEN
  DUP LINEARITY-AFFINE   = IF DROP ." AFFINE"   EXIT THEN
  DUP LINEARITY-RELEVANT = IF DROP ." RELEVANT" EXIT THEN
  DUP LINEARITY-DEBUG    = IF DROP ." DEBUG"    EXIT THEN
  . ." (unknown)" ;

: CELL-DUMP ( addr -- )
  CR
  ." ┌─── Semantos Cell (" SCELL-SIZE . ." bytes) ───" CR
  DUP CELL-MAGIC-VALID? IF ." │ Magic:      OK" ELSE ." │ Magic:      INVALID" THEN CR
  DUP CELL-VERSION@     ." │ Version:    " . CR
  DUP CELL-LINEARITY@   ." │ Linearity:  " .LINEARITY CR
  DUP CELL-FLAGS@       ." │ Flags:      " HEX . DECIMAL CR
  DUP CELL-REF-COUNT@   ." │ Ref count:  " . CR
  DUP CELL-TIMESTAMP@   ." │ Timestamp:  " . CR
  DUP CELL-CELL-COUNT@  ." │ Cell count: " . CR
  DUP CELL-PAYLOAD-LEN@ ." │ Payload:    " . ." bytes" CR
  DUP CELL-TYPE-HASH-ADDR ." │ TypeHash:  " 8 .HEX-BYTES ." ..." CR
  DUP CELL-OWNER-ID-ADDR  ." │ OwnerID:   " 8 .HEX-BYTES ." ..." CR
  DROP
  ." └─────────────────────────────────────" CR ;
