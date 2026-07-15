\ tests/run-sighash.fs — sighash.fs unit tests (no crypto required)
REQUIRE ../bootstrap.fs

VARIABLE TEST-PASS  0 TEST-PASS !
VARIABLE TEST-FAIL  0 TEST-FAIL !

: PASS ( -- )  1 TEST-PASS +!  ." PASS" CR ;
: FAIL ( -- )  1 TEST-FAIL +!  ." FAIL" CR ;
: ASSERT-EQ ( got expected -- )  = IF PASS ELSE FAIL THEN ;
: ASSERT-TRUE  ( flag -- )  IF PASS ELSE FAIL THEN ;

\ Scratch buffer for varint tests
CREATE VI-BUF 16 ALLOT

\ ── TS01: WRITE-VARINT 1-byte form ───────────────────────────────────────────

: TS01 ( -- )
  ." TS01: WRITE-VARINT 1-byte" CR
  252 VI-BUF WRITE-VARINT  1 ASSERT-EQ
  VI-BUF C@  252 = ASSERT-TRUE ;

\ ── TS02: WRITE-VARINT 3-byte form (0xFD prefix) ─────────────────────────────

: TS02 ( -- )
  ." TS02: WRITE-VARINT 3-byte" CR
  $1234 VI-BUF WRITE-VARINT  3 ASSERT-EQ
  VI-BUF C@      $FD = ASSERT-TRUE
  VI-BUF 1+ LE16@ $1234 = ASSERT-TRUE ;

\ ── TS03: WRITE-VARINT 5-byte form (0xFE prefix) ─────────────────────────────

: TS03 ( -- )
  ." TS03: WRITE-VARINT 5-byte" CR
  $10000 VI-BUF WRITE-VARINT  5 ASSERT-EQ
  VI-BUF C@        $FE = ASSERT-TRUE
  VI-BUF 1+ LE32@  $10000 = ASSERT-TRUE ;

\ ── TS04: READ-VARINT 1-byte round-trip ──────────────────────────────────────

: TS04 ( -- )
  ." TS04: READ-VARINT 1-byte round-trip" CR
  0 VI-BUF C!
  VI-BUF READ-VARINT   1 ASSERT-EQ  0 ASSERT-EQ ;

\ ── TS05: READ-VARINT 3-byte round-trip ──────────────────────────────────────

: TS05 ( -- )
  ." TS05: READ-VARINT 3-byte round-trip" CR
  $CAFE VI-BUF WRITE-VARINT DROP
  VI-BUF READ-VARINT   3 ASSERT-EQ  $CAFE ASSERT-EQ ;

\ ── TS06: WRITE/READ-VARINT boundary values ──────────────────────────────────

: TS06 ( -- )
  ." TS06: varint boundary -- 252 is 1-byte, 253 is 3-byte" CR
  252 VI-BUF WRITE-VARINT  1 ASSERT-EQ
  VI-BUF READ-VARINT        1 ASSERT-EQ  252 ASSERT-EQ
  253 VI-BUF WRITE-VARINT  3 ASSERT-EQ
  VI-BUF READ-VARINT        3 ASSERT-EQ  253 ASSERT-EQ ;

\ ── TS07: TxInput accessors round-trip ───────────────────────────────────────

: TS07 ( -- )
  ." TS07: TxInput accessor round-trip" CR
  TX-CTX-ZERO
  1 TCX-INPUT-COUNT!

  \ Build a fake txid at offset 0 of TXI #0
  0 TXI-TXID-ADDR                      \ addr of txid field
  32 0 DO $AA OVER I + C! LOOP DROP    \ fill with 0xAA bytes

  $DEADBEEF 0 TXI-VOUT!
  $CAFEBABE 0 TXI-SEQUENCE!
  64        0 TXI-SCRIPT-LEN!

  0 TXI-TXID-ADDR C@   $AA = ASSERT-TRUE
  0 TXI-VOUT@    $DEADBEEF = ASSERT-TRUE
  0 TXI-SEQUENCE@  $CAFEBABE = ASSERT-TRUE
  0 TXI-SCRIPT-LEN@  64 = ASSERT-TRUE ;

\ ── TS08: TxOutput accessors round-trip ──────────────────────────────────────

: TS08 ( -- )
  ." TS08: TxOutput accessor round-trip" CR
  TX-CTX-ZERO
  1 TCX-OUTPUT-COUNT!

  123456789 0 TXO-VALUE!
  25        0 TXO-SCRIPT-LEN!
  0 TXO-SCRIPT-ADDR               \ fill first 4 bytes with test pattern
  $DEADBEEF OVER LE32!  DROP

  0 TXO-VALUE@      123456789 = ASSERT-TRUE
  0 TXO-SCRIPT-LEN@  25 = ASSERT-TRUE
  0 TXO-SCRIPT-ADDR LE32@  $DEADBEEF = ASSERT-TRUE ;

\ ── TS09: SIGHASH_FORKID check in COMPUTE-SIGHASH ────────────────────────────
\ Wrapper words keep arguments off the stack so CATCH restores a clean frame.

: -CALL-NO-FORKID   ( -- )  S" dummy"  1   COMPUTE-SIGHASH DROP ;
: -CALL-WITH-FORKID ( -- )  S" script" $41 COMPUTE-SIGHASH DROP ;

: TS09 ( -- )
  ." TS09: COMPUTE-SIGHASH rejects sighash without FORKID" CR
  ['] -CALL-NO-FORKID CATCH 0<> ASSERT-TRUE ;

\ ── TS10: SIGHASH_ALL|FORKID flag accepted (aborts later on missing crypto) ──

: TS10 ( -- )
  ." TS10: COMPUTE-SIGHASH accepts ALL|FORKID before SHA256D check" CR
  ['] -CALL-WITH-FORKID CATCH 0<> ASSERT-TRUE ;

\ ── TS11: PARSE-TX-CONTEXT — minimal 1-in 1-out coinbase-style tx ─────────────

\ Build a minimal raw transaction in a buffer:
\   version=1 (4B LE) | varint(1) | input | varint(1) | output | locktime=0 (4B LE)
\ Input (no scriptSig, sequence=0xFFFFFFFF):
\   prev_txid[32]=0x00..., prev_vout=0 (4B LE), scriptSig_len=0 (varint 1B), seq (4B LE)
\ Output: value=5000 sats (8B LE), script_len=1 (varint 1B), script[1]=0x51 (OP_1)

CREATE MINI-TX  256 ALLOT

: BUILD-MINI-TX ( -- len )
  MINI-TX
  \ version = 1
  1 OVER LE32!  4 +
  \ input count = 1
  1 OVER C!  1+
  \ prev_txid: 32 zero bytes (already zeroed by ALLOT but be explicit)
  DUP 32 0 FILL  32 +
  \ prev_vout = 0
  0 OVER LE32!  4 +
  \ scriptSig len = 0 (varint, 1 byte)
  0 OVER C!  1+
  \ nSequence = 0xFFFFFFFF
  -1 OVER LE32!  4 +
  \ output count = 1
  1 OVER C!  1+
  \ value = 5000 sats
  5000 OVER LE64!  8 +
  \ script len = 1 (varint, 1 byte)
  1 OVER C!  1+
  \ script = 0x51 (OP_1)
  $51 OVER C!  1+
  \ locktime = 0
  0 OVER LE32!  4 +
  MINI-TX -  ;  \ return byte length

: TS11 ( -- )
  ." TS11: PARSE-TX-CONTEXT minimal tx" CR
  MINI-TX 256 0 FILL   \ zero the buffer
  BUILD-MINI-TX        \ len on stack
  MINI-TX SWAP         \ raw-addr raw-len
  0                    \ input-idx = 0
  5000                 \ input-value = 5000 sats
  PARSE-TX-CONTEXT

  TCX-VERSION@      1 = ASSERT-TRUE
  TCX-LOCKTIME@     0 = ASSERT-TRUE
  TCX-INPUT-COUNT@  1 = ASSERT-TRUE
  TCX-OUTPUT-COUNT@ 1 = ASSERT-TRUE
  TCX-INPUT-VALUE@  5000 = ASSERT-TRUE
  TCX-CUR-INPUT@    0 = ASSERT-TRUE
  0 TXI-VOUT@       0 = ASSERT-TRUE
  0 TXI-SEQUENCE@   $FFFFFFFF = ASSERT-TRUE
  0 TXO-VALUE@      5000 = ASSERT-TRUE
  0 TXO-SCRIPT-LEN@ 1 = ASSERT-TRUE
  0 TXO-SCRIPT-ADDR C@  $51 = ASSERT-TRUE ;

\ ── Run all ───────────────────────────────────────────────────────────────────

TS01 TS02 TS03 TS04 TS05 TS06 TS07 TS08 TS09 TS10 TS11

CR .( ── Sighash results ───────────────────────────────────) CR
.( PASS: ) TEST-PASS @ . CR
.( FAIL: ) TEST-FAIL @ . CR
: .SIGHASH-SUMMARY ( -- )
  TEST-FAIL @ 0= IF ." All sighash tests passed." CR
               ELSE ." Some sighash tests FAILED." CR THEN ;
.SIGHASH-SUMMARY
