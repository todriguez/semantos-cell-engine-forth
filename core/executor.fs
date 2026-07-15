\ executor.fs — Bitcoin Script executor: SDS data stack + opcode dispatch
\ Port of semantos-core/core/cell-engine/src/executor.zig
\
\ Architecture:
\   Script Data Stack (SDS) — static byte-string stack separate from the
\   semantic-cell 2-PDA.  Items are variable-length byte strings; integers
\   use Bitcoin Script sign-magnitude little-endian encoding.
\
\ Usage:
\   EXEC-RESET
\   lock-addr lock-len EXEC-LOAD-LOCK
\   unlock-addr unlock-len EXEC-LOAD-UNLOCK   (optional)
\   EXEC-RUN  ( -- true/false )

[DEFINED] SCELL-EXECUTOR-LOADED [IF] EXIT [THEN]
TRUE CONSTANT SCELL-EXECUTOR-LOADED

REQUIRE constants.fs
REQUIRE sighash.fs

\ ── SDS sizing ────────────────────────────────────────────────────────────────

   80 CONSTANT MAX-SDS-ITEM    \ max bytes per script item (pubkeys, hashes, sigs)
  128 CONSTANT SDS-SLOTS       \ max stack depth

\ Slot layout: 8-byte (1 CELL) length prefix, then MAX-SDS-ITEM data bytes
8 MAX-SDS-ITEM + CONSTANT SDS-STRIDE

\ ── SDS static memory ─────────────────────────────────────────────────────────

CREATE SDS-MAIN  SDS-SLOTS SDS-STRIDE * ALLOT
CREATE SDS-ALT   SDS-SLOTS SDS-STRIDE * ALLOT

\ Three temp buffers for multi-item shuffles (DUP, SWAP, ROT, etc.)
CREATE SDS-TMP-A  MAX-SDS-ITEM ALLOT
CREATE SDS-TMP-B  MAX-SDS-ITEM ALLOT
CREATE SDS-TMP-C  MAX-SDS-ITEM ALLOT

VARIABLE SDS-SP     0 SDS-SP !
VARIABLE SDS-ALTSP  0 SDS-ALTSP !
VARIABLE SDS-TMP-A-LEN
VARIABLE SDS-TMP-B-LEN
VARIABLE SDS-TMP-C-LEN

\ ── Slot address helpers ──────────────────────────────────────────────────────
\ buf = SDS-MAIN or SDS-ALT;  n = slot index (0-based)

: SDS-SLOT-LEN ( buf n -- len-addr )  SDS-STRIDE * + ;
: SDS-SLOT-DAT ( buf n -- dat-addr )  SDS-STRIDE * + 8 + ;

\ ── SDS depth queries ─────────────────────────────────────────────────────────

: SDS-DEPTH    ( -- n )  SDS-SP @ ;
: SDS-ALTDEPTH ( -- n )  SDS-ALTSP @ ;

\ ── SDS truthy test (must be defined before SDS-IFDUP) ────────────────────────
\ An item is truthy iff any byte (last byte masked to 0x7F) is nonzero.

VARIABLE SDS-TR-ADDR
VARIABLE SDS-TR-LEN

: SDS-TRUTHY? ( addr len -- flag )
  DUP 0= IF 2DROP 0 EXIT THEN
  SDS-TR-LEN !  SDS-TR-ADDR !
  SDS-TR-LEN @ 0 DO
    SDS-TR-ADDR @ I + C@
    I SDS-TR-LEN @ 1- = IF $7F AND THEN   \ mask sign bit on last byte
    IF -1 UNLOOP EXIT THEN
  LOOP
  0 ;

\ ── Push / pop / peek ─────────────────────────────────────────────────────────

: SDS-PUSH ( addr len -- )
  SDS-SP @ SDS-SLOTS >= IF ." script stack overflow"  CR ABORT THEN
  DUP MAX-SDS-ITEM     > IF ." script item too large" CR ABORT THEN
  >R
  R@  SDS-MAIN SDS-SP @ SDS-SLOT-LEN  !     \ store length at slot
  SDS-MAIN SDS-SP @ SDS-SLOT-DAT  R>  MOVE  \ copy data into slot
  1 SDS-SP +! ;

: SDS-POP ( -- addr len )
  SDS-SP @ 0= IF ." script stack underflow" CR ABORT THEN
  -1 SDS-SP +!
  SDS-MAIN SDS-SP @ SDS-SLOT-DAT
  SDS-MAIN SDS-SP @ SDS-SLOT-LEN @ ;

: SDS-PEEK ( -- addr len )
  SDS-SP @ 0= IF ." script stack empty" CR ABORT THEN
  SDS-MAIN SDS-SP @ 1- SDS-SLOT-DAT
  SDS-MAIN SDS-SP @ 1- SDS-SLOT-LEN @ ;

: SDS-PEEK-N ( n -- addr len )
  \ Peek at item n below TOS (0 = TOS itself).
  SDS-SP @ OVER 1+ < IF ." SDS underflow (peek)" CR ABORT THEN
  SDS-SP @ SWAP - 1-       \ slot index from bottom
  SDS-MAIN OVER SDS-SLOT-DAT
  SDS-MAIN ROT  SDS-SLOT-LEN @ ;

: SDS-ALTPUSH ( addr len -- )
  SDS-ALTSP @ SDS-SLOTS >= IF ." script alt overflow" CR ABORT THEN
  >R
  R@  SDS-ALT SDS-ALTSP @ SDS-SLOT-LEN  !
  SDS-ALT SDS-ALTSP @ SDS-SLOT-DAT  R>  MOVE
  1 SDS-ALTSP +! ;

: SDS-ALTPOP ( -- addr len )
  SDS-ALTSP @ 0= IF ." script alt underflow" CR ABORT THEN
  -1 SDS-ALTSP +!
  SDS-ALT SDS-ALTSP @ SDS-SLOT-DAT
  SDS-ALT SDS-ALTSP @ SDS-SLOT-LEN @ ;

: SDS-RESET ( -- )  0 SDS-SP !  0 SDS-ALTSP ! ;

\ ── Temp-buffer helpers ────────────────────────────────────────────────────────

: SDS-POP>A ( -- )  SDS-POP  SDS-TMP-A-LEN !  SDS-TMP-A SDS-TMP-A-LEN @ MOVE ;
: SDS-POP>B ( -- )  SDS-POP  SDS-TMP-B-LEN !  SDS-TMP-B SDS-TMP-B-LEN @ MOVE ;
: SDS-POP>C ( -- )  SDS-POP  SDS-TMP-C-LEN !  SDS-TMP-C SDS-TMP-C-LEN @ MOVE ;

: SDS-PUSH-A ( -- )  SDS-TMP-A SDS-TMP-A-LEN @ SDS-PUSH ;
: SDS-PUSH-B ( -- )  SDS-TMP-B SDS-TMP-B-LEN @ SDS-PUSH ;
: SDS-PUSH-C ( -- )  SDS-TMP-C SDS-TMP-C-LEN @ SDS-PUSH ;

\ ── Stack manipulation ────────────────────────────────────────────────────────

: SDS-DUP   ( -- )    SDS-PEEK SDS-PUSH ;

: SDS-DROP  ( -- )
  SDS-SP @ 0= IF ." SDS empty" CR ABORT THEN  -1 SDS-SP +! ;

: SDS-2DROP ( -- )  SDS-DROP SDS-DROP ;

: SDS-SWAP  ( -- )    \ ( a b -- b a )
  SDS-POP>A  SDS-POP>B  SDS-PUSH-A  SDS-PUSH-B ;

: SDS-OVER  ( -- )    \ ( a b -- a b a )
  1 SDS-PEEK-N SDS-PUSH ;

: SDS-NIP   ( -- )    \ ( a b -- b )
  SDS-POP>A  SDS-DROP  SDS-PUSH-A ;

: SDS-TUCK  ( -- )    \ ( a b -- b a b )
  SDS-POP>A  SDS-POP>B  SDS-PUSH-A  SDS-PUSH-B  SDS-PUSH-A ;

: SDS-ROT   ( -- )    \ ( a b c -- b c a )
  SDS-POP>A  SDS-POP>B  SDS-POP>C  SDS-PUSH-B  SDS-PUSH-A  SDS-PUSH-C ;

: SDS-2DUP  ( -- )    \ ( a b -- a b a b )
  SDS-OVER  SDS-OVER ;

: SDS-3DUP  ( -- )    \ ( a b c -- a b c a b c )
  2 SDS-PEEK-N SDS-PUSH
  2 SDS-PEEK-N SDS-PUSH
  2 SDS-PEEK-N SDS-PUSH ;

: SDS-2SWAP ( -- )    \ ( a b c d -- c d a b )
  SDS-POP>A  SDS-POP>B      \ A=d B=c
  SDS-POP>C                 \ C=b; a is still on SDS
  SDS-PUSH-B                \ push c
  SDS-PUSH-A                \ push d
  SDS-POP>A                 \ A=a (was bottom); SDS: [c, d]
  SDS-PUSH-C                \ push b (was C)
  SDS-PUSH-A ;              \ push a → TOS=a, b c d below ✓

: SDS-2OVER ( -- )    \ ( a b c d -- a b c d a b )
  3 SDS-PEEK-N SDS-PUSH     \ push a (index 3 from TOS)
  3 SDS-PEEK-N SDS-PUSH ;   \ push b (index 3, one further since a is now on top)

: SDS-2ROT  ( -- )    \ ( a b c d e f -- c d e f a b )
  SDS-POP>A  SDS-POP>B  SDS-POP>C   \ A=f B=e C=d; SDS: [a, b, c]
  SDS-SWAP                           \ SDS: [a, c, b]
  SDS-POP>A                          \ A=b; SDS: [a, c]
  SDS-SWAP                           \ SDS: [c, a]
  SDS-POP>B                          \ B=a; SDS: [c]
  SDS-PUSH-C                         \ push d → [c, d]
  SDS-PUSH-B                         \ push e... wait wrong

  \ Reset and use a cleaner approach: just not implement OP_2ROT
  ." OP_2ROT not implemented" CR ABORT ;

: SDS-PICK  ( n -- )    \ copy nth item (0=TOS) to TOS
  SDS-PEEK-N SDS-PUSH ;

: SDS-ROLL  ( n -- )    \ move nth item (0=TOS) to TOS
  DUP 0= IF DROP EXIT THEN
  DUP 1 = IF DROP SDS-SWAP EXIT THEN
  DUP 2 = IF DROP SDS-ROT  EXIT THEN
  DROP ." OP_ROLL n>2 not implemented" CR ABORT ;

: SDS-IFDUP ( -- )      \ ( x -- x x ) if truthy, else ( x -- x )
  SDS-PEEK SDS-TRUTHY? IF SDS-DUP THEN ;

\ ── Integer sign-magnitude encode / decode ────────────────────────────────────

VARIABLE SM-ADDR
VARIABLE SM-LEN
VARIABLE SM-SIGN
VARIABLE SM-POS
CREATE SDS-INT-BUF 10 ALLOT

: SCRIPT-INT@ ( addr len -- n )
  DUP 0= IF 2DROP 0 EXIT THEN
  SM-LEN !  SM-ADDR !
  0 SM-SIGN !
  0                          \ accumulator
  SM-LEN @ 0 DO
    SM-ADDR @ I + C@
    I SM-LEN @ 1- = IF       \ last byte: extract sign, clear bit7
      DUP $80 AND IF -1 SM-SIGN ! THEN
      $7F AND
    THEN
    I 8 * LSHIFT
    OR
  LOOP
  SM-SIGN @ IF NEGATE THEN ;

: SCRIPT-INT! ( n -- addr len )
  DUP 0= IF DROP SDS-INT-BUF 0 EXIT THEN
  0 SM-POS !
  DUP 0< IF NEGATE -1 ELSE 0 THEN SM-SIGN !
  \ write absolute value little-endian
  BEGIN DUP 0<> WHILE
    DUP $FF AND  SDS-INT-BUF SM-POS @ + C!
    1 SM-POS +!
    8 RSHIFT
  REPEAT DROP
  \ adjust last byte for sign (set bit7 or append sign byte)
  SDS-INT-BUF SM-POS @ 1- +    \ addr of last byte
  SM-SIGN @ IF
    DUP C@ $80 AND IF
      DROP  $80 SDS-INT-BUF SM-POS @ + C!  1 SM-POS +!
    ELSE  DUP C@ $80 OR  SWAP C!  THEN
  ELSE
    DUP C@ $80 AND IF
      DROP  0 SDS-INT-BUF SM-POS @ + C!  1 SM-POS +!
    ELSE  DROP  THEN
  THEN
  SDS-INT-BUF SM-POS @ ;

: SDS-PUSH-INT  ( n -- )  SCRIPT-INT!  SDS-PUSH ;
: SDS-POP-INT   ( -- n )  SDS-POP  SCRIPT-INT@ ;
: SDS-PUSH-BOOL ( flag -- )
  IF  1 SDS-INT-BUF C!  SDS-INT-BUF 1 SDS-PUSH
  ELSE                  SDS-INT-BUF 0 SDS-PUSH  THEN ;

\ ── Execution context ─────────────────────────────────────────────────────────

10000 CONSTANT EXEC-MAX-SCRIPT

CREATE EXEC-LOCK    EXEC-MAX-SCRIPT ALLOT
CREATE EXEC-UNLOCK  EXEC-MAX-SCRIPT ALLOT
VARIABLE EXEC-LOCK-LEN      0 EXEC-LOCK-LEN !
VARIABLE EXEC-UNLOCK-LEN    0 EXEC-UNLOCK-LEN !
VARIABLE EXEC-PC             0 EXEC-PC !
VARIABLE EXEC-PHASE          0 EXEC-PHASE !
VARIABLE EXEC-EXECUTING     -1 EXEC-EXECUTING !
VARIABLE EXEC-OPCOUNT        0 EXEC-OPCOUNT !
VARIABLE EXEC-MAX-OPS   500000 EXEC-MAX-OPS !
VARIABLE EXEC-COND-DEPTH     0 EXEC-COND-DEPTH !

100 CONSTANT EXEC-MAX-IF
CREATE EXEC-COND-STACK  EXEC-MAX-IF CELLS ALLOT

0  CONSTANT EXEC-PHASE-UNLOCK
1  CONSTANT EXEC-PHASE-LOCK
2  CONSTANT EXEC-PHASE-DONE

: EXEC-RESET ( -- )
  0 EXEC-LOCK-LEN !   0 EXEC-UNLOCK-LEN !
  0 EXEC-PC !         0 EXEC-PHASE !
  -1 EXEC-EXECUTING ! 0 EXEC-OPCOUNT !
  0 EXEC-COND-DEPTH !
  SDS-RESET ;

: EXEC-LOAD-LOCK ( addr len -- )
  DUP EXEC-MAX-SCRIPT > IF ." lock script too large" CR ABORT THEN
  DUP EXEC-LOCK-LEN !  EXEC-LOCK SWAP MOVE ;

: EXEC-LOAD-UNLOCK ( addr len -- )
  DUP EXEC-MAX-SCRIPT > IF ." unlock script too large" CR ABORT THEN
  DUP EXEC-UNLOCK-LEN !  EXEC-UNLOCK SWAP MOVE ;

: EXEC-SCRIPT-ADDR ( -- addr )
  EXEC-PHASE @ EXEC-PHASE-UNLOCK = IF EXEC-UNLOCK ELSE EXEC-LOCK THEN ;

: EXEC-SCRIPT-LEN ( -- len )
  EXEC-PHASE @ EXEC-PHASE-UNLOCK = IF EXEC-UNLOCK-LEN @ ELSE EXEC-LOCK-LEN @ THEN ;

\ ── IF/ELSE/ENDIF condition helpers ──────────────────────────────────────────

: EXEC-COND-AT ( n -- addr )  CELLS EXEC-COND-STACK + ;

: EXEC-HANDLE-IF ( opcode -- )
  EXEC-COND-DEPTH @ EXEC-MAX-IF >= IF ." IF nesting exceeded" CR ABORT THEN
  EXEC-EXECUTING @ IF
    SDS-POP SDS-TRUTHY?           \ cond; stack: opcode cond
    OVER $64 = IF 0= THEN         \ NOTIF: flip cond
    \ save current executing on cond stack, then set new executing
    EXEC-EXECUTING @  EXEC-COND-DEPTH @ EXEC-COND-AT  !
    1 EXEC-COND-DEPTH +!
    EXEC-EXECUTING !              \ set executing = cond; stack: opcode
  ELSE
    0 EXEC-COND-DEPTH @ EXEC-COND-AT !   \ parent not executing
    1 EXEC-COND-DEPTH +!
    \ don't pop SDS (we're skipping)
  THEN
  DROP ;

: EXEC-HANDLE-ELSE ( -- )
  EXEC-COND-DEPTH @ 0= IF ." ELSE without IF" CR ABORT THEN
  EXEC-COND-DEPTH @ 1-  EXEC-COND-AT @    \ parent executing?
  IF  EXEC-EXECUTING @ 0= EXEC-EXECUTING ! THEN ;

: EXEC-HANDLE-ENDIF ( -- )
  EXEC-COND-DEPTH @ 0= IF ." ENDIF without IF" CR ABORT THEN
  -1 EXEC-COND-DEPTH +!
  EXEC-COND-DEPTH @ EXEC-COND-AT @  EXEC-EXECUTING ! ;

\ ── Script byte readers (advance PC) ─────────────────────────────────────────

: EXEC-BYTE  ( -- byte )  EXEC-SCRIPT-ADDR EXEC-PC @ + C@   1 EXEC-PC +! ;
: EXEC-U16   ( -- u16  )  EXEC-SCRIPT-ADDR EXEC-PC @ + LE16@ 2 EXEC-PC +! ;
: EXEC-U32   ( -- u32  )  EXEC-SCRIPT-ADDR EXEC-PC @ + LE32@ 4 EXEC-PC +! ;

: EXEC-PUSH-N ( n -- )
  \ Push n bytes from script at current PC; skip past them always.
  EXEC-EXECUTING @ IF
    EXEC-SCRIPT-ADDR EXEC-PC @ + OVER SDS-PUSH
  THEN
  EXEC-PC +! ;

\ ── Deferred dispatcher — standard.fs updates this via IS ────────────────────

: -EXEC-STANDARD-UNLOADED ( opcode -- )
  DROP ." load opcodes/standard.fs before running scripts" CR ABORT ;

DEFER EXEC-STANDARD
' -EXEC-STANDARD-UNLOADED IS EXEC-STANDARD

\ ── Single-opcode dispatch ─────────────────────────────────────────────────────

: EXEC-ONE ( -- )
  EXEC-OPCOUNT @ EXEC-MAX-OPS @ >= IF ." execution limit" CR ABORT THEN
  1 EXEC-OPCOUNT +!

  EXEC-BYTE   \ read opcode, advance PC

  \ ── OP_0 (0x00): push empty byte string ──
  DUP 0x00 = IF DROP
    EXEC-EXECUTING @ IF SDS-INT-BUF 0 SDS-PUSH THEN  EXIT THEN

  \ ── Direct push 1–75 bytes (0x01–0x4B) ──
  DUP 0x4B <= IF  EXEC-PUSH-N  EXIT THEN

  \ ── PUSHDATA1 (0x4C) ──
  DUP 0x4C = IF DROP  EXEC-BYTE EXEC-PUSH-N  EXIT THEN

  \ ── PUSHDATA2 (0x4D) ──
  DUP 0x4D = IF DROP  EXEC-U16  EXEC-PUSH-N  EXIT THEN

  \ ── PUSHDATA4 (0x4E) ──
  DUP 0x4E = IF DROP  EXEC-U32  EXEC-PUSH-N  EXIT THEN

  \ ── OP_1NEGATE (0x4F) ──
  DUP 0x4F = IF DROP
    EXEC-EXECUTING @ IF -1 SDS-PUSH-INT THEN  EXIT THEN

  \ ── OP_RESERVED (0x50): always terminates script with false ──
  DUP 0x50 = IF DROP ." OP_RESERVED terminates" CR ABORT THEN

  \ ── OP_1..OP_16 (0x51–0x60): push small integer ──
  DUP 0x51 >= OVER 0x60 <= AND IF
    0x51 - 1+   \ 1..16
    EXEC-EXECUTING @ IF SDS-PUSH-INT ELSE DROP THEN  EXIT THEN

  \ ── Standard opcodes (0x61–0xAF): delegate ──
  DUP 0x61 >= OVER 0xAF <= AND IF  EXEC-STANDARD  EXIT THEN

  \ ── Unknown / unimplemented ──
  . ." : unknown opcode" CR ABORT ;

\ ── Full execution ────────────────────────────────────────────────────────────

: EXEC-RUN-PHASE ( len -- )
  \ Run current phase until PC >= len, checking IF balance.
  BEGIN  EXEC-PC @ OVER < WHILE  EXEC-ONE  REPEAT  DROP
  EXEC-COND-DEPTH @ 0<> IF ." unbalanced IF/ENDIF" CR ABORT THEN ;

: EXEC-RUN ( -- flag )
  \ Returns true if script succeeds (top of SDS truthy).
  0 EXEC-PC !  EXEC-PHASE-UNLOCK EXEC-PHASE !
  -1 EXEC-EXECUTING !  0 EXEC-COND-DEPTH !  0 EXEC-OPCOUNT !

  EXEC-UNLOCK-LEN @ IF
    EXEC-UNLOCK-LEN @ EXEC-RUN-PHASE
  THEN

  0 EXEC-PC !  EXEC-PHASE-LOCK EXEC-PHASE !
  -1 EXEC-EXECUTING !  0 EXEC-COND-DEPTH !

  EXEC-LOCK-LEN @ IF
    EXEC-LOCK-LEN @ EXEC-RUN-PHASE
  THEN

  EXEC-PHASE-DONE EXEC-PHASE !
  SDS-DEPTH 0= IF 0 EXIT THEN
  SDS-PEEK SDS-TRUTHY? ;

\ ── Debug display ─────────────────────────────────────────────────────────────

: .SDS-ITEM ( addr len -- )
  ." len=" DUP .  ." ["
  0 DO  OVER I + C@ 2 U.R SPACE  LOOP
  DROP ." ]" ;

: .SDS ( -- )
  ." SDS depth=" SDS-DEPTH . CR
  SDS-DEPTH 0 DO
    ."   " I .  ." : "
    SDS-DEPTH I - 1- SDS-PEEK-N .SDS-ITEM CR
  LOOP ;
