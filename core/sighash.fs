\ sighash.fs — BIP143 preimage construction for BSV OP_CHECKSIG
\ Port of semantos-core/core/cell-engine/src/sighash.zig
\
\ BSV REQUIRES SIGHASH_FORKID (0x40) on every signature.
\ Call flow: populate TX-CTX via PARSE-TX-CONTEXT, then COMPUTE-SIGHASH.
\ Limits (embedded profile): 4 inputs, 4 outputs, 1024-byte output scripts.

[DEFINED] SCELL-SIGHASH-LOADED [IF] EXIT [THEN]
TRUE CONSTANT SCELL-SIGHASH-LOADED

REQUIRE constants.fs
REQUIRE cell.fs

\ ── SIGHASH type flags ────────────────────────────────────────────────────────

  1 CONSTANT SIGHASH-ALL
  2 CONSTANT SIGHASH-NONE
  3 CONSTANT SIGHASH-SINGLE
128 CONSTANT SIGHASH-ANYONECANPAY   \ 0x80
 64 CONSTANT SIGHASH-FORKID         \ 0x40  BSV mandatory on every sig
 31 CONSTANT SIGHASH-MASK           \ 0x1F  isolates base type

\ ── TxInput layout (44 bytes) ─────────────────────────────────────────────────

 0 CONSTANT TXI-OFF-TXID          \ 32 bytes raw
32 CONSTANT TXI-OFF-VOUT          \  4 bytes LE u32
36 CONSTANT TXI-OFF-SCRIPT-LEN    \  4 bytes LE u32 (scriptSig len — skipped)
40 CONSTANT TXI-OFF-SEQUENCE      \  4 bytes LE u32
44 CONSTANT TXI-SIZE

\ ── TxOutput layout (1036 bytes) ──────────────────────────────────────────────

   0 CONSTANT TXO-OFF-VALUE        \  8 bytes LE u64
   8 CONSTANT TXO-OFF-SCRIPT       \ 1024 bytes raw
1032 CONSTANT TXO-OFF-SCRIPT-LEN   \  4 bytes LE u32
1036 CONSTANT TXO-SIZE

\ ── TxContext header layout ───────────────────────────────────────────────────

 0 CONSTANT TCX-OFF-VERSION        \  4 bytes LE u32
 4 CONSTANT TCX-OFF-LOCKTIME       \  4 bytes LE u32
 8 CONSTANT TCX-OFF-CUR-INPUT      \  4 bytes LE u32
12 CONSTANT TCX-OFF-CUR-OUTPUT     \  4 bytes LE u32
16 CONSTANT TCX-OFF-INPUT-VALUE    \  8 bytes LE u64
24 CONSTANT TCX-OFF-INPUT-COUNT    \  4 bytes LE u32
28 CONSTANT TCX-OFF-OUTPUT-COUNT   \  4 bytes LE u32
32 CONSTANT TCX-HEADER-SIZE

4 CONSTANT MAX-TX-INPUTS
4 CONSTANT MAX-TX-OUTPUTS

\ Byte offsets of arrays inside TX-CTX.
MAX-TX-INPUTS TXI-SIZE * TCX-HEADER-SIZE + CONSTANT TCX-OUTPUTS-OFF
TCX-OUTPUTS-OFF MAX-TX-OUTPUTS TXO-SIZE * + CONSTANT TCX-SIZE

\ ── Static storage ────────────────────────────────────────────────────────────

CREATE TX-CTX              TCX-SIZE ALLOT
CREATE SIGHASH-PREVOUTS-BUF  144 ALLOT  \ 4 × 36 bytes
CREATE SIGHASH-SEQ-BUF        16 ALLOT  \ 4 × 4 bytes
CREATE SIGHASH-OUTPUTS-BUF  4148 ALLOT  \ 4 × (8+5+1024)
CREATE SIGHASH-PREIMAGE-BUF 1200 ALLOT  \ ample for 4+32+32+36+5+1024+8+4+32+4+4
CREATE SIGHASH-HASH-WORK      32 ALLOT  \ intermediate double-SHA256 result
CREATE SIGHASH-HASH-PREVOUTS  32 ALLOT
CREATE SIGHASH-HASH-SEQUENCE  32 ALLOT
CREATE SIGHASH-HASH-OUTPUTS   32 ALLOT
CREATE SIGHASH-RESULT         32 ALLOT  \ output of COMPUTE-SIGHASH

VARIABLE SIGHASH-POS      \ running byte offset into current buffer
VARIABLE SIGHASH-SUB-ADDR \ subscript address (stashed during COMPUTE-SIGHASH)
VARIABLE SIGHASH-SUB-LEN  \ subscript length
VARIABLE PARSE-INPUT-IDX  \ saved input-idx during PARSE-TX-CONTEXT
VARIABLE PARSE-INPUT-VAL  \ saved input-value during PARSE-TX-CONTEXT

: TX-CTX-ZERO ( -- )  TX-CTX TCX-SIZE 0 FILL ;
TX-CTX-ZERO

\ ── TxContext scalar accessors ────────────────────────────────────────────────

: TCX-VERSION@      ( -- u32 )  TX-CTX TCX-OFF-VERSION       + LE32@ ;
: TCX-LOCKTIME@     ( -- u32 )  TX-CTX TCX-OFF-LOCKTIME      + LE32@ ;
: TCX-CUR-INPUT@    ( -- u32 )  TX-CTX TCX-OFF-CUR-INPUT     + LE32@ ;
: TCX-CUR-OUTPUT@   ( -- u32 )  TX-CTX TCX-OFF-CUR-OUTPUT    + LE32@ ;
: TCX-INPUT-VALUE@  ( -- u64 )  TX-CTX TCX-OFF-INPUT-VALUE   + LE64@ ;
: TCX-INPUT-COUNT@  ( -- u32 )  TX-CTX TCX-OFF-INPUT-COUNT   + LE32@ ;
: TCX-OUTPUT-COUNT@ ( -- u32 )  TX-CTX TCX-OFF-OUTPUT-COUNT  + LE32@ ;

: TCX-VERSION!      ( u32 -- )  TX-CTX TCX-OFF-VERSION       + LE32! ;
: TCX-LOCKTIME!     ( u32 -- )  TX-CTX TCX-OFF-LOCKTIME      + LE32! ;
: TCX-CUR-INPUT!    ( u32 -- )  TX-CTX TCX-OFF-CUR-INPUT     + LE32! ;
: TCX-CUR-OUTPUT!   ( u32 -- )  TX-CTX TCX-OFF-CUR-OUTPUT    + LE32! ;
: TCX-INPUT-VALUE!  ( u64 -- )  TX-CTX TCX-OFF-INPUT-VALUE   + LE64! ;
: TCX-INPUT-COUNT!  ( u32 -- )  TX-CTX TCX-OFF-INPUT-COUNT   + LE32! ;
: TCX-OUTPUT-COUNT! ( u32 -- )  TX-CTX TCX-OFF-OUTPUT-COUNT  + LE32! ;

\ ── TxInput accessors ( n = 0-based index ) ───────────────────────────────────

: TXI-ADDR       ( n -- addr )  TXI-SIZE * TCX-HEADER-SIZE + TX-CTX + ;
: TXI-TXID-ADDR  ( n -- addr )  TXI-ADDR TXI-OFF-TXID       + ;
: TXI-VOUT@      ( n -- u32  )  TXI-ADDR TXI-OFF-VOUT       + LE32@ ;
: TXI-SCRIPT-LEN@ ( n -- u32  )  TXI-ADDR TXI-OFF-SCRIPT-LEN + LE32@ ;
: TXI-SEQUENCE@  ( n -- u32  )  TXI-ADDR TXI-OFF-SEQUENCE   + LE32@ ;
: TXI-VOUT!      ( u32 n -- )   TXI-ADDR TXI-OFF-VOUT       + LE32! ;
: TXI-SCRIPT-LEN! ( u32 n -- )   TXI-ADDR TXI-OFF-SCRIPT-LEN + LE32! ;
: TXI-SEQUENCE!  ( u32 n -- )   TXI-ADDR TXI-OFF-SEQUENCE   + LE32! ;
: TXI-TXID!      ( src n -- )   TXI-TXID-ADDR 32 MOVE ;

\ ── TxOutput accessors ( n = 0-based index ) ──────────────────────────────────

: TXO-ADDR       ( n -- addr )  TXO-SIZE * TCX-OUTPUTS-OFF + TX-CTX + ;
: TXO-VALUE@     ( n -- u64  )  TXO-ADDR TXO-OFF-VALUE      + LE64@ ;
: TXO-SCRIPT-ADDR ( n -- addr )  TXO-ADDR TXO-OFF-SCRIPT     + ;
: TXO-SCRIPT-LEN@ ( n -- u32  )  TXO-ADDR TXO-OFF-SCRIPT-LEN + LE32@ ;
: TXO-VALUE!     ( u64 n -- )   TXO-ADDR TXO-OFF-VALUE      + LE64! ;
: TXO-SCRIPT-LEN! ( u32 n -- )   TXO-ADDR TXO-OFF-SCRIPT-LEN + LE32! ;
: TXO-SCRIPT!    ( src len n -- )  TXO-ADDR TXO-OFF-SCRIPT  + SWAP MOVE ;

\ ── SHA256D-INTO stub ─────────────────────────────────────────────────────────
\ Replaced by the real word when crypto/crypto.fs is loaded first.

[DEFINED] SHA256D-INTO [IF] [ELSE]
  : SHA256D-INTO ( src-addr src-len dst-addr -- )
    DROP 2DROP
    CR ." SHA256D-INTO: load crypto/crypto.fs before COMPUTE-SIGHASH" CR ABORT ;
[THEN]

\ ── VarInt encode / decode ────────────────────────────────────────────────────
\ WRITE-VARINT ( val buf -- bytes-written )
\   LE16!, LE32!, LE64! are ( u addr -- ): TOS=addr, TOS-1=value.
\   After '$FF OVER C! 1+' the stack is ( val buf+1 ) — direct LE write, no SWAP.

: WRITE-VARINT ( val buf -- bytes-written )
  OVER 253 < IF
    TUCK C!   \ TUCK: (val buf → buf val buf); C!(val,buf) → buf; DROP buf
    DROP 1
  ELSE
    OVER 65536 < IF
      $FD OVER C!   \ store prefix at buf; stack: val buf
      1+            \ val buf+1
      LE16!         \ LE16!(val, buf+1) consumes both
      3
    ELSE
      OVER $100000000 < IF
        $FE OVER C!
        1+
        LE32!
        5
      ELSE
        $FF OVER C!
        1+
        LE64!
        9
      THEN
    THEN
  THEN ;

\ READ-VARINT ( buf -- val bytes-consumed )

: READ-VARINT ( buf -- val bytes-consumed )
  DUP C@
  DUP 253 < IF
    NIP 1             \ val 1  (NIP removes buf)
  ELSE
    DROP              \ remove first-byte duplicate; stack: buf
    DUP C@
    253 = IF 1+ LE16@ 3
    ELSE DUP C@ 254 = IF 1+ LE32@ 5
    ELSE               1+ LE64@ 9
    THEN THEN
  THEN ;

\ ── BIP143 hash component builders ───────────────────────────────────────────
\ Each writes its SHA256D result into SIGHASH-HASH-WORK.

: BUILD-HASH-PREVOUTS ( -- )
  \ SHA256D( concat(txid || vout_LE32) for all inputs )
  SIGHASH-PREVOUTS-BUF SIGHASH-POS !
  0 BEGIN DUP TCX-INPUT-COUNT@ < WHILE
    DUP TXI-TXID-ADDR  SIGHASH-POS @ 32 MOVE  32 SIGHASH-POS +!
    DUP TXI-VOUT@      SIGHASH-POS @    LE32!   4 SIGHASH-POS +!
    1+
  REPEAT DROP
  SIGHASH-PREVOUTS-BUF
  SIGHASH-POS @ SIGHASH-PREVOUTS-BUF -
  SIGHASH-HASH-WORK SHA256D-INTO ;

: BUILD-HASH-SEQUENCE ( -- )
  \ SHA256D( concat(sequence_LE32) for all inputs )
  SIGHASH-SEQ-BUF SIGHASH-POS !
  0 BEGIN DUP TCX-INPUT-COUNT@ < WHILE
    DUP TXI-SEQUENCE@  SIGHASH-POS @ LE32!  4 SIGHASH-POS +!
    1+
  REPEAT DROP
  SIGHASH-SEQ-BUF
  SIGHASH-POS @ SIGHASH-SEQ-BUF -
  SIGHASH-HASH-WORK SHA256D-INTO ;

: BUILD-HASH-OUTPUTS-ALL ( -- )
  \ SHA256D( concat(value_LE64 || varint(script_len) || script) for all outputs )
  SIGHASH-OUTPUTS-BUF SIGHASH-POS !
  0 BEGIN DUP TCX-OUTPUT-COUNT@ < WHILE
    DUP TXO-VALUE@      SIGHASH-POS @    LE64!   8 SIGHASH-POS +!
    DUP TXO-SCRIPT-LEN@ SIGHASH-POS @
      WRITE-VARINT SIGHASH-POS +!
    DUP TXO-SCRIPT-ADDR  OVER TXO-SCRIPT-LEN@  \ src len
      SIGHASH-POS @ SWAP MOVE                   \ MOVE(src, pos, len) via SWAP
      DUP TXO-SCRIPT-LEN@ SIGHASH-POS +!
    1+
  REPEAT DROP
  SIGHASH-OUTPUTS-BUF
  SIGHASH-POS @ SIGHASH-OUTPUTS-BUF -
  SIGHASH-HASH-WORK SHA256D-INTO ;

: BUILD-HASH-OUTPUT-SINGLE ( idx -- )
  \ SHA256D( value_LE64 || varint(script_len) || script ) for output idx.
  SIGHASH-OUTPUTS-BUF SIGHASH-POS !
  DUP TXO-VALUE@      SIGHASH-POS @ LE64!  8 SIGHASH-POS +!
  DUP TXO-SCRIPT-LEN@ SIGHASH-POS @ WRITE-VARINT SIGHASH-POS +!
  DUP TXO-SCRIPT-ADDR OVER TXO-SCRIPT-LEN@
    SIGHASH-POS @ SWAP MOVE
  TXO-SCRIPT-LEN@ SIGHASH-POS +!
  SIGHASH-OUTPUTS-BUF
  SIGHASH-POS @ SIGHASH-OUTPUTS-BUF -
  SIGHASH-HASH-WORK SHA256D-INTO ;

\ ── Hash component selectors ─────────────────────────────────────────────────

: PREPARE-HASH-PREVOUTS ( anyone_can_pay -- )
  IF   SIGHASH-HASH-PREVOUTS 32 0 FILL
  ELSE BUILD-HASH-PREVOUTS
       SIGHASH-HASH-WORK SIGHASH-HASH-PREVOUTS 32 MOVE
  THEN ;

: PREPARE-HASH-SEQUENCE ( anyone_can_pay base_type -- )
  \ Non-zero only when !anyone_can_pay AND base = ALL.
  SIGHASH-ALL = SWAP 0= AND IF
    BUILD-HASH-SEQUENCE
    SIGHASH-HASH-WORK SIGHASH-HASH-SEQUENCE 32 MOVE
  ELSE SIGHASH-HASH-SEQUENCE 32 0 FILL
  THEN ;

: PREPARE-HASH-OUTPUTS ( base_type -- )
  DUP SIGHASH-ALL = IF
    DROP BUILD-HASH-OUTPUTS-ALL
    SIGHASH-HASH-WORK SIGHASH-HASH-OUTPUTS 32 MOVE
  ELSE DUP SIGHASH-SINGLE = IF
    DROP TCX-CUR-INPUT@
    DUP TCX-OUTPUT-COUNT@ < IF
      BUILD-HASH-OUTPUT-SINGLE
      SIGHASH-HASH-WORK SIGHASH-HASH-OUTPUTS 32 MOVE
    ELSE DROP SIGHASH-HASH-OUTPUTS 32 0 FILL
    THEN
  ELSE DROP SIGHASH-HASH-OUTPUTS 32 0 FILL
  THEN THEN ;

\ ── COMPUTE-SIGHASH ───────────────────────────────────────────────────────────
\ ( subscript-addr subscript-len sighash-type -- hash-addr )
\ TX-CTX must be populated before calling.  Returns SIGHASH-RESULT (32 bytes).

: COMPUTE-SIGHASH ( subscript-addr subscript-len sighash-type -- hash-addr )
  DUP SIGHASH-FORKID AND 0= IF
    CR ." COMPUTE-SIGHASH: SIGHASH_FORKID (0x40) required on BSV" CR ABORT
  THEN

  \ Stash subscript so it's off the stack during preimage assembly.
  >R   \ sighash-type → R
  SIGHASH-SUB-LEN !
  SIGHASH-SUB-ADDR !

  \ Pre-compute the three BIP143 hashes.
  R@ SIGHASH-ANYONECANPAY AND 0<>  PREPARE-HASH-PREVOUTS
  R@ SIGHASH-ANYONECANPAY AND 0<>
  R@ SIGHASH-MASK AND              PREPARE-HASH-SEQUENCE
  R@ SIGHASH-MASK AND              PREPARE-HASH-OUTPUTS

  \ Assemble preimage into SIGHASH-PREIMAGE-BUF.
  SIGHASH-PREIMAGE-BUF SIGHASH-POS !

  \ 1. nVersion (4B LE)
  TCX-VERSION@ SIGHASH-POS @ LE32!  4 SIGHASH-POS +!

  \ 2. hashPrevouts (32B)
  SIGHASH-HASH-PREVOUTS SIGHASH-POS @ 32 MOVE  32 SIGHASH-POS +!

  \ 3. hashSequence (32B)
  SIGHASH-HASH-SEQUENCE SIGHASH-POS @ 32 MOVE  32 SIGHASH-POS +!

  \ 4. outpoint of current input: txid (32B) + vout (4B LE)
  TCX-CUR-INPUT@ DUP TXI-TXID-ADDR SIGHASH-POS @ 32 MOVE  32 SIGHASH-POS +!
                 TXI-VOUT@ SIGHASH-POS @ LE32!              4 SIGHASH-POS +!

  \ 5. scriptCode: varint(len) + bytes
  SIGHASH-SUB-LEN @ SIGHASH-POS @ WRITE-VARINT SIGHASH-POS +!
  SIGHASH-SUB-ADDR @ SIGHASH-SUB-LEN @ SIGHASH-POS @ SWAP MOVE
  SIGHASH-SUB-LEN @ SIGHASH-POS +!

  \ 6. value of UTXO being spent (8B LE)
  TCX-INPUT-VALUE@ SIGHASH-POS @ LE64!  8 SIGHASH-POS +!

  \ 7. nSequence of current input (4B LE)
  TCX-CUR-INPUT@ TXI-SEQUENCE@ SIGHASH-POS @ LE32!  4 SIGHASH-POS +!

  \ 8. hashOutputs (32B)
  SIGHASH-HASH-OUTPUTS SIGHASH-POS @ 32 MOVE  32 SIGHASH-POS +!

  \ 9. nLockTime (4B LE)
  TCX-LOCKTIME@ SIGHASH-POS @ LE32!  4 SIGHASH-POS +!

  \ 10. nHashType (4B LE)
  R> $FF AND SIGHASH-POS @ LE32!  4 SIGHASH-POS +!

  \ SHA256D(preimage) → SIGHASH-RESULT
  SIGHASH-PREIMAGE-BUF
  SIGHASH-POS @ SIGHASH-PREIMAGE-BUF -
  SIGHASH-RESULT SHA256D-INTO

  SIGHASH-RESULT ;

\ ── PARSE-TX-CONTEXT ──────────────────────────────────────────────────────────
\ ( raw-addr raw-len input-idx input-value -- )
\ Parse raw serialised transaction bytes into TX-CTX.
\ Format: version(4) + varint(n_in) + inputs + varint(n_out) + outputs + locktime(4)

: PARSE-TX-CONTEXT ( raw-addr raw-len input-idx input-value -- )
  \ Save metadata to static vars before TX-CTX-ZERO (not in wire format).
  PARSE-INPUT-VAL !   \ store input_value;   stack: raw-addr raw-len input-idx
  PARSE-INPUT-IDX !   \ store input-idx;     stack: raw-addr raw-len
  DROP                \ drop raw-len;        stack: raw-addr
  TX-CTX-ZERO
  PARSE-INPUT-VAL @ TCX-INPUT-VALUE!
  PARSE-INPUT-IDX @ TCX-CUR-INPUT!
  0 SIGHASH-POS !     \ SIGHASH-POS is our running byte offset into raw-addr

  \ Version (4B LE)
  DUP SIGHASH-POS @ + LE32@ TCX-VERSION!
  4 SIGHASH-POS +!

  \ Input count (varint)
  DUP SIGHASH-POS @ + READ-VARINT   \ raw-addr count bytes-consumed
  SIGHASH-POS +!
  TCX-INPUT-COUNT!                   \ raw-addr

  \ Parse inputs
  0 BEGIN DUP TCX-INPUT-COUNT@ < WHILE   \ raw-addr i
    \ prev_txid (32B)
    OVER SIGHASH-POS @ +  OVER TXI-TXID-ADDR  32 MOVE
    32 SIGHASH-POS +!
    \ prev_vout (4B LE)
    OVER SIGHASH-POS @ + LE32@  OVER TXI-VOUT!
    4 SIGHASH-POS +!
    \ scriptSig length (varint) — record and skip the bytes
    OVER SIGHASH-POS @ + READ-VARINT   \ raw-addr i script_len bytes
    SIGHASH-POS +!
    OVER TXI-SCRIPT-LEN!               \ raw-addr i
    DUP TXI-SCRIPT-LEN@ SIGHASH-POS +! \ skip scriptSig bytes
    \ nSequence (4B LE)
    OVER SIGHASH-POS @ + LE32@  OVER TXI-SEQUENCE!
    4 SIGHASH-POS +!
    1+
  REPEAT DROP   \ raw-addr

  \ Output count (varint)
  DUP SIGHASH-POS @ + READ-VARINT
  SIGHASH-POS +!
  TCX-OUTPUT-COUNT!   \ raw-addr

  \ Parse outputs
  0 BEGIN DUP TCX-OUTPUT-COUNT@ < WHILE   \ raw-addr i
    \ value (8B LE)
    OVER SIGHASH-POS @ + LE64@  OVER TXO-VALUE!
    8 SIGHASH-POS +!
    \ script length (varint)
    OVER SIGHASH-POS @ + READ-VARINT   \ raw-addr i script_len bytes
    SIGHASH-POS +!
    OVER TXO-SCRIPT-LEN!               \ raw-addr i
    \ copy script bytes
    OVER SIGHASH-POS @ +               \ raw-addr i src_ptr
    OVER TXO-SCRIPT-ADDR               \ raw-addr i src_ptr dst_ptr
    2 PICK TXO-SCRIPT-LEN@             \ raw-addr i src_ptr dst_ptr script_len
    MOVE                               \ raw-addr i
    DUP TXO-SCRIPT-LEN@ SIGHASH-POS +!
    1+
  REPEAT DROP   \ raw-addr

  \ Locktime (4B LE) — raw-addr is consumed by the + in the expression
  SIGHASH-POS @ + LE32@ TCX-LOCKTIME! ;

\ ── Display ───────────────────────────────────────────────────────────────────

: .SIGHASH-TYPE ( u8 -- )
  DUP SIGHASH-FORKID      AND IF ." |FORKID"      THEN
  DUP SIGHASH-ANYONECANPAY AND IF ." |ANYONECANPAY" THEN
  SIGHASH-MASK AND
  DUP SIGHASH-ALL    = IF DROP ." ALL"    EXIT THEN
  DUP SIGHASH-NONE   = IF DROP ." NONE"   EXIT THEN
  DUP SIGHASH-SINGLE = IF DROP ." SINGLE" EXIT THEN
  . ." (unknown)" ;

: .TX-CTX ( -- )
  CR ." TxContext:" CR
  ."   version:      " TCX-VERSION@      . CR
  ."   locktime:     " TCX-LOCKTIME@     . CR
  ."   input_value:  " TCX-INPUT-VALUE@  . ." sats" CR
  ."   cur_input:    " TCX-CUR-INPUT@    . CR
  ."   input_count:  " TCX-INPUT-COUNT@  . CR
  ."   output_count: " TCX-OUTPUT-COUNT@ . CR ;
