\ tests/run-executor.fs — executor.fs + standard.fs unit tests
REQUIRE ../bootstrap.fs

VARIABLE TEST-PASS  0 TEST-PASS !
VARIABLE TEST-FAIL  0 TEST-FAIL !

: PASS ( -- )  1 TEST-PASS +!  ." PASS" CR ;
: FAIL ( -- )  1 TEST-FAIL +!  ." FAIL" CR ;
: ASSERT-TRUE  ( flag -- )  IF PASS ELSE FAIL THEN ;
: ASSERT-FALSE ( flag -- )  0= ASSERT-TRUE ;
: ASSERT-EQ    ( got expected -- )  = ASSERT-TRUE ;

\ ── TE01: EXEC-RESET clears state ────────────────────────────────────────────

: TE01 ( -- )
  ." TE01: EXEC-RESET clears state" CR
  EXEC-RESET
  SDS-DEPTH 0 =           ASSERT-TRUE
  SDS-ALTDEPTH 0 =        ASSERT-TRUE
  EXEC-PC @  0 =          ASSERT-TRUE
  EXEC-OPCOUNT @ 0 =      ASSERT-TRUE ;

\ ── TE02: SDS push-int / pop-int round-trip ───────────────────────────────────

: TE02 ( -- )
  ." TE02: SDS-PUSH-INT / SDS-POP-INT round-trip" CR
  EXEC-RESET
  0         SDS-PUSH-INT   SDS-POP-INT   0 =       ASSERT-TRUE
  1         SDS-PUSH-INT   SDS-POP-INT   1 =       ASSERT-TRUE
  -1        SDS-PUSH-INT   SDS-POP-INT  -1 =       ASSERT-TRUE
  127       SDS-PUSH-INT   SDS-POP-INT   127 =     ASSERT-TRUE
  -128      SDS-PUSH-INT   SDS-POP-INT  -128 =     ASSERT-TRUE
  32767     SDS-PUSH-INT   SDS-POP-INT   32767 =   ASSERT-TRUE
  -32768    SDS-PUSH-INT   SDS-POP-INT  -32768 =   ASSERT-TRUE
  100000    SDS-PUSH-INT   SDS-POP-INT   100000 =  ASSERT-TRUE ;

\ ── TE03: SDS-TRUTHY? ─────────────────────────────────────────────────────────

CREATE ZERO3 3 ALLOT  ZERO3 3 0 FILL
CREATE NEGZ  2 ALLOT  0 NEGZ C!  $80 NEGZ 1+ C!  \ negative zero: \x00\x80

: TE03 ( -- )
  ." TE03: SDS-TRUTHY?" CR
  EXEC-RESET
  SDS-INT-BUF 0 SDS-TRUTHY?   ASSERT-FALSE   \ empty → false
  ZERO3 3 SDS-TRUTHY?          ASSERT-FALSE   \ all-zeros → false
  NEGZ 2 SDS-TRUTHY?           ASSERT-FALSE   \ negative-zero → false
  SDS-INT-BUF 1 ( 0x01 in buf )               \ make sure byte is 1
    1 SDS-INT-BUF C!
    SDS-INT-BUF 1 SDS-TRUTHY?  ASSERT-TRUE
  SDS-INT-BUF $80 ( ← sets first byte )
    $80 SDS-INT-BUF C!
    SDS-INT-BUF 1 SDS-TRUTHY?  ASSERT-TRUE ;  \ $80 is NOT a sign-only byte here (len=1, masked to $00)

\ Fix TE03 last case: single byte $80 → masked $80 & $7F = $00 → falsy.
\ The correct truthy single-byte is anything non-zero when masked.

: TE03 ( -- )
  ." TE03: SDS-TRUTHY?" CR
  EXEC-RESET
  SDS-INT-BUF 0 SDS-TRUTHY?   ASSERT-FALSE   \ empty → false
  ZERO3 3 SDS-TRUTHY?          ASSERT-FALSE   \ all zeros → false
  NEGZ 2 SDS-TRUTHY?           ASSERT-FALSE   \ negative zero → false
  1 SDS-INT-BUF C!
  SDS-INT-BUF 1 SDS-TRUTHY?   ASSERT-TRUE    \ \x01 → true
  $81 SDS-INT-BUF C!
  SDS-INT-BUF 1 SDS-TRUTHY?   ASSERT-TRUE ;  \ \x81 → last-byte & $7F = $01 → true

\ ── TE04: Script execution — push opcodes ────────────────────────────────────
\ OP_1 = $51, OP_2 = $52, OP_16 = $60, OP_0 = $00, OP_1NEGATE = $4F

: TE04 ( -- )
  ." TE04: push opcodes OP_0 OP_1 OP_2 OP_16 OP_1NEGATE" CR
  EXEC-RESET
  S\" \x51"  EXEC-LOAD-LOCK  EXEC-UNLOCK-LEN 0= drop  \ OP_1
  0 EXEC-PC !  EXEC-PHASE-LOCK EXEC-PHASE !  -1 EXEC-EXECUTING !  0 EXEC-COND-DEPTH !
  EXEC-LOCK-LEN @ EXEC-RUN-PHASE
  SDS-POP-INT   1 =    ASSERT-TRUE

  SDS-RESET  0 EXEC-PC !
  S\" \x00"  EXEC-LOCK SWAP MOVE  1 EXEC-LOCK-LEN !  \ OP_0
  EXEC-PHASE-LOCK EXEC-PHASE !  -1 EXEC-EXECUTING !  0 EXEC-COND-DEPTH !
  EXEC-LOCK-LEN @ EXEC-RUN-PHASE
  SDS-POP    NIP 0 =   ASSERT-TRUE   \ length 0 → empty (false)

  SDS-RESET  0 EXEC-PC !
  S\" \x4F"  EXEC-LOCK SWAP MOVE  1 EXEC-LOCK-LEN !  \ OP_1NEGATE
  EXEC-PHASE-LOCK EXEC-PHASE !  -1 EXEC-EXECUTING !  0 EXEC-COND-DEPTH !
  EXEC-LOCK-LEN @ EXEC-RUN-PHASE
  SDS-POP-INT  -1 =    ASSERT-TRUE

  SDS-RESET  0 EXEC-PC !
  S\" \x60"  EXEC-LOCK SWAP MOVE  1 EXEC-LOCK-LEN !  \ OP_16
  EXEC-PHASE-LOCK EXEC-PHASE !  -1 EXEC-EXECUTING !  0 EXEC-COND-DEPTH !
  EXEC-LOCK-LEN @ EXEC-RUN-PHASE
  SDS-POP-INT  16 =    ASSERT-TRUE ;

\ ── TE05: Arithmetic via EXEC-RUN ─────────────────────────────────────────────
\ Unlock: OP_2 OP_3 → Lock: OP_ADD → result 5 on SDS; EXEC-RUN checks TOS truthy.
\ Actually EXEC-RUN pops and checks truthy; 5 is truthy → returns true.
\ For a proper equality test: unlock=OP_2 OP_3, lock=OP_ADD OP_5 OP_EQUAL.

: TE05 ( -- )
  ." TE05: 2 + 3 = 5 via EXEC-RUN" CR
  EXEC-RESET
  \ unlock: OP_2 OP_3  ($52 $53)
  S\" \x52\x53"  EXEC-LOAD-UNLOCK
  \ lock: OP_ADD OP_5 OP_EQUAL  ($93 $55 $87)
  S\" \x93\x55\x87"  EXEC-LOAD-LOCK
  EXEC-RUN ASSERT-TRUE ;

\ ── TE06: Subtraction 7 - 3 = 4 ─────────────────────────────────────────────

: TE06 ( -- )
  ." TE06: 7 - 3 = 4 via OP_SUB OP_EQUAL" CR
  EXEC-RESET
  S\" \x57\x53"  EXEC-LOAD-UNLOCK    \ OP_7 OP_3
  S\" \x94\x54\x87"  EXEC-LOAD-LOCK  \ OP_SUB OP_4 OP_EQUAL
  EXEC-RUN ASSERT-TRUE ;

\ ── TE07: OP_DUP ─────────────────────────────────────────────────────────────

: TE07 ( -- )
  ." TE07: OP_DUP duplicates TOS" CR
  EXEC-RESET
  S\" \x55"  EXEC-LOAD-UNLOCK         \ OP_5
  S\" \x76\x76\x93\x5A\x87"  EXEC-LOAD-LOCK   \ OP_DUP OP_DUP OP_ADD OP_10 OP_EQUAL
  EXEC-RUN ASSERT-TRUE ;

\ ── TE08: OP_SWAP ─────────────────────────────────────────────────────────────

: TE08 ( -- )
  ." TE08: OP_SWAP" CR
  EXEC-RESET
  S\" \x51\x53"  EXEC-LOAD-UNLOCK         \ push 1, push 3
  \ after swap TOS=1, 2nd=3; 3 - 1 = 2 = OP_2
  S\" \x7C\x94\x52\x87"  EXEC-LOAD-LOCK   \ OP_SWAP OP_SUB OP_2 OP_EQUAL
  EXEC-RUN ASSERT-TRUE ;

\ ── TE09: IF/ELSE/ENDIF — true branch ────────────────────────────────────────
\ Script: OP_1 OP_IF OP_7 OP_ELSE OP_9 OP_ENDIF
\ Bytes:  $51  $63  $57   $67  $59   $68

: TE09 ( -- )
  ." TE09: IF true branch → OP_7" CR
  EXEC-RESET
  S\" \x51\x63\x57\x67\x59\x68\x57\x87"  EXEC-LOAD-LOCK
  \ OP_1 OP_IF OP_7 OP_ELSE OP_9 OP_ENDIF OP_7 OP_EQUAL → true
  EXEC-RUN ASSERT-TRUE ;

\ ── TE10: IF/ELSE/ENDIF — false branch ───────────────────────────────────────
\ Script: OP_0 OP_IF OP_7 OP_ELSE OP_9 OP_ENDIF OP_9 OP_EQUAL

: TE10 ( -- )
  ." TE10: IF false branch → OP_9" CR
  EXEC-RESET
  S\" \x00\x63\x57\x67\x59\x68\x59\x87"  EXEC-LOAD-LOCK
  EXEC-RUN ASSERT-TRUE ;

\ ── TE11: OP_NOT ─────────────────────────────────────────────────────────────
\ OP_0 OP_NOT → 1 (true); OP_1 OP_NOT → 0 (false)

: TE11 ( -- )
  ." TE11: OP_NOT" CR
  EXEC-RESET
  S\" \x00\x91"  EXEC-LOAD-LOCK   \ OP_0 OP_NOT → truthy
  EXEC-RUN ASSERT-TRUE

  EXEC-RESET
  S\" \x51\x91"  EXEC-LOAD-LOCK   \ OP_1 OP_NOT → falsy
  EXEC-RUN ASSERT-FALSE ;

\ ── TE12: OP_EQUAL byte-string equality ─────────────────────────────────────
\ Push two 3-byte data items via PUSHDATA; they're equal → OP_EQUAL → true.
\ Script: $03 $AA $BB $CC  $03 $AA $BB $CC  $87
\ (push 3 bytes 0xAA 0xBB 0xCC, same again, then OP_EQUAL)

: TE12 ( -- )
  ." TE12: OP_EQUAL on byte strings" CR
  EXEC-RESET
  S\" \x03\xAA\xBB\xCC\x03\xAA\xBB\xCC\x87"  EXEC-LOAD-LOCK
  EXEC-RUN ASSERT-TRUE ;

\ ── TE13: OP_WITHIN ───────────────────────────────────────────────────────────
\ 5 OP_WITHIN [3, 8) → true;  2 OP_WITHIN [3, 8) → false

: TE13 ( -- )
  ." TE13: OP_WITHIN" CR
  EXEC-RESET
  \ OP_5 OP_3 OP_8 OP_WITHIN  ($55 $53 $58 $A5)
  S\" \x55\x53\x58\xA5"  EXEC-LOAD-LOCK
  EXEC-RUN ASSERT-TRUE

  EXEC-RESET
  \ OP_2 OP_3 OP_8 OP_WITHIN  ($52 $53 $58 $A5)
  S\" \x52\x53\x58\xA5"  EXEC-LOAD-LOCK
  EXEC-RUN ASSERT-FALSE ;

\ ── TE14: OP_TOALTSTACK / OP_FROMALTSTACK ────────────────────────────────────
\ OP_7 OP_TOALTSTACK OP_3 OP_FROMALTSTACK OP_ADD OP_10 OP_EQUAL

: TE14 ( -- )
  ." TE14: OP_TOALTSTACK / OP_FROMALTSTACK" CR
  EXEC-RESET
  S\" \x57\x6B\x53\x6C\x93\x5A\x87"  EXEC-LOAD-LOCK
  EXEC-RUN ASSERT-TRUE ;

\ ── TE15: OP_DEPTH ───────────────────────────────────────────────────────────
\ OP_1 OP_2 OP_3 OP_DEPTH → 3 on TOS; OP_3 OP_EQUAL

: TE15 ( -- )
  ." TE15: OP_DEPTH" CR
  EXEC-RESET
  S\" \x51\x52\x53\x74\x53\x87"  EXEC-LOAD-LOCK
  EXEC-RUN ASSERT-TRUE ;

\ ── TE16: OP_SIZE ─────────────────────────────────────────────────────────────
\ Push 3-byte item, OP_SIZE → pushes 3, OP_3 OP_EQUAL; item still on stack.

: TE16 ( -- )
  ." TE16: OP_SIZE" CR
  EXEC-RESET
  \ $03 $AA $BB $CC $82 $53 $87 $75 = push 3 bytes, SIZE, OP_3, EQUAL, DROP
  S\" \x03\xAA\xBB\xCC\x82\x53\x87\x75"  EXEC-LOAD-LOCK
  EXEC-RUN ASSERT-TRUE ;

\ ── TE17: min/max ─────────────────────────────────────────────────────────────

: TE17 ( -- )
  ." TE17: OP_MIN OP_MAX" CR
  EXEC-RESET
  \ OP_3 OP_7 OP_MIN OP_3 OP_EQUAL  ($53 $57 $A3 $53 $87)
  S\" \x53\x57\xA3\x53\x87"  EXEC-LOAD-LOCK
  EXEC-RUN ASSERT-TRUE

  EXEC-RESET
  \ OP_3 OP_7 OP_MAX OP_7 OP_EQUAL  ($53 $57 $A4 $57 $87)
  S\" \x53\x57\xA4\x57\x87"  EXEC-LOAD-LOCK
  EXEC-RUN ASSERT-TRUE ;

\ ── Run all ───────────────────────────────────────────────────────────────────

TE01 TE02 TE03 TE04 TE05 TE06 TE07 TE08
TE09 TE10 TE11 TE12 TE13 TE14 TE15 TE16 TE17

CR .( ── Executor results ──────────────────────────────────) CR
.( PASS: ) TEST-PASS @ . CR
.( FAIL: ) TEST-FAIL @ . CR
: .EXEC-SUMMARY ( -- )
  TEST-FAIL @ 0= IF ." All executor tests passed." CR
               ELSE ." Some executor tests FAILED." CR THEN ;
.EXEC-SUMMARY
